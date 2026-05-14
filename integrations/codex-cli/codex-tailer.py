#!/usr/bin/env python3
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# Codex CLI session tailer → Crux Daemon observation capture.
#
# Watches the `~/.codex/sessions/**/rollout-*.jsonl` files Codex writes per
# conversation and POSTs each new event to a running corecruxd as a signed
# observation. Persists a per-file cursor so it resumes cleanly across
# restarts. Fire-and-forget against the daemon: a daemon outage MUST NOT
# cause the tailer to crash or lose progress.
#
# Codex rollout file format (one JSON object per line):
#   {"timestamp": "...", "type": "session_meta"|"event_msg"|"response_item"|...,
#    "payload": { ... }}
#
# The first line of every rollout is `session_meta`, whose `payload.id` is the
# session UUID we use as the corecruxd session id.
#
# Usage:
#   python3 codex-tailer.py                    # default once-and-done
#   python3 codex-tailer.py --watch            # long-running poll loop
#   python3 codex-tailer.py --since 2026-05-01 # backfill from a date
#   python3 codex-tailer.py --print-only       # debug: no POSTs

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import signal
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable

DEFAULT_CODEX_ROOT = Path(os.environ.get("CODEX_ROOT", "~/.codex")).expanduser()
DEFAULT_CURSOR_PATH = DEFAULT_CODEX_ROOT / ".crux-tailer-cursor.json"
DEFAULT_DAEMON_URL = os.environ.get("CORECRUXD_URL", "http://127.0.0.1:14800")
DEFAULT_TIMEOUT = float(os.environ.get("CRUX_OBSERVE_TIMEOUT", "1.0"))
DEFAULT_POLL_SECONDS = float(os.environ.get("CRUX_TAILER_POLL_SECONDS", "2.0"))
MAX_PAYLOAD_BYTES = 240 * 1024  # leave 16KB headroom under daemon's 256KB cap

ROLLOUT_FILENAME = re.compile(r"^rollout-.*\.jsonl$")


# ── Cursor persistence ───────────────────────────────────────────────────


def load_cursor(path: Path) -> dict[str, int]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save_cursor(path: Path, cursor: dict[str, int]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(cursor, sort_keys=True))
        tmp.replace(path)
    except OSError as err:
        print(f"warning: failed to save cursor: {err}", file=sys.stderr)


# ── Rollout file discovery ───────────────────────────────────────────────


def discover_rollout_files(codex_root: Path, include_archived: bool) -> list[Path]:
    """Find every rollout-*.jsonl Codex has produced, sorted by mtime ascending
    so we tail in roughly the order events happened."""
    candidates: list[Path] = []
    for base in (codex_root / "sessions", codex_root / "archived_sessions" if include_archived else None):
        if base is None or not base.exists():
            continue
        for entry in base.rglob("rollout-*.jsonl"):
            if entry.is_file() and ROLLOUT_FILENAME.match(entry.name):
                candidates.append(entry)
    candidates.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0.0)
    return candidates


# ── Observation emission ─────────────────────────────────────────────────


class Emitter:
    def __init__(self, daemon_url: str, *, auth_token: str | None, timeout: float, print_only: bool) -> None:
        self.daemon_url = daemon_url.rstrip("/")
        self.auth_token = auth_token
        self.timeout = timeout
        self.print_only = print_only
        self.sent = 0
        self.failed = 0

    def emit(self, session_id: str, event: dict, source_path: Path) -> None:
        # Map a Codex rollout line to the observation envelope. We pass the
        # entire event through as payload so the daemon can replay it later,
        # but compress big payloads to stay under the daemon's 256KB cap.
        payload = {
            "codex_event_type": event.get("type"),
            "codex_event_ts": event.get("timestamp"),
            "source_file": str(source_path),
            "raw": _truncate_event(event),
        }
        body = {
            "kind": _kind_for_event(event),
            "provider": "codex-cli",
            "client_ts": event.get("timestamp"),
            "payload": payload,
        }
        if self.print_only:
            print(json.dumps({"session_id": session_id, **body}))
            return

        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"{self.daemon_url}/v1/sessions/{session_id}/observations",
            data=data,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        if self.auth_token:
            req.add_header("Authorization", f"Bearer {self.auth_token}")
        # Daemons running in `dev_scopes` auth mode accept scopes via this
        # header. Default covers POST /v1/sessions/{id}/observations.
        req.add_header(
            "X-Corecrux-Scopes",
            os.environ.get("CORECRUXD_SCOPES", "sessions:write admin:read"),
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp.read()
            self.sent += 1
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as err:
            self.failed += 1
            # Cursor advances only AFTER a successful emit, so a daemon outage
            # parks the cursor and we retry on the next poll iteration.
            raise EmitFailure(str(err)) from err


class EmitFailure(RuntimeError):
    pass


def _kind_for_event(event: dict) -> str:
    """Map Codex event types to the conventional observation kinds. We keep
    the original type in payload.codex_event_type for full fidelity."""
    et = event.get("type")
    if et == "session_meta":
        return "session_start"
    if et == "event_msg":
        return "tool_use"
    if et == "response_item":
        return "model_response"
    return "codex_event"


def _truncate_event(event: dict) -> dict:
    raw = json.dumps(event, default=str)
    if len(raw) <= MAX_PAYLOAD_BYTES:
        return event
    return {
        "_truncated": True,
        "_original_bytes": len(raw),
        "excerpt": raw[:MAX_PAYLOAD_BYTES],
    }


# ── File tailing ─────────────────────────────────────────────────────────


def session_id_for_file(path: Path) -> str | None:
    """Read the first line of a rollout file to extract the session UUID
    from session_meta. Cached implicitly via cursor (we only call this when
    cursor offset == 0)."""
    try:
        with path.open("rb") as f:
            first = f.readline()
        meta = json.loads(first)
        if meta.get("type") == "session_meta":
            return meta.get("payload", {}).get("id")
    except (OSError, json.JSONDecodeError):
        return None
    return None


def tail_file(
    path: Path,
    cursor: dict[str, int],
    emitter: Emitter,
    *,
    session_id_cache: dict[str, str],
    since_ts: float | None,
) -> int:
    """Read new lines since the last cursor offset; emit each as an
    observation. Returns the number of lines emitted from this file in this
    pass."""
    key = str(path)
    offset = cursor.get(key, 0)
    sid = session_id_cache.get(key)
    if sid is None:
        sid = session_id_for_file(path)
        if sid is None:
            return 0
        session_id_cache[key] = sid

    emitted = 0
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            f.seek(offset)
            for line in f:
                if not line.strip():
                    offset += len(line.encode("utf-8"))
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    offset += len(line.encode("utf-8"))
                    continue

                # `since` lower-bound (per-event ts, not file mtime).
                if since_ts is not None:
                    ev_ts = _parse_ts(event.get("timestamp"))
                    if ev_ts is not None and ev_ts < since_ts:
                        offset += len(line.encode("utf-8"))
                        continue

                try:
                    emitter.emit(sid, event, path)
                except EmitFailure:
                    # Daemon down or rejecting: park, retry next pass.
                    return emitted
                offset += len(line.encode("utf-8"))
                emitted += 1
    except OSError as err:
        print(f"warning: read {path}: {err}", file=sys.stderr)
        return emitted
    cursor[key] = offset
    return emitted


def _parse_ts(value) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


# ── CLI ─────────────────────────────────────────────────────────────────


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--codex-root", default=str(DEFAULT_CODEX_ROOT), type=Path)
    p.add_argument("--cursor-path", default=str(DEFAULT_CURSOR_PATH), type=Path)
    p.add_argument("--daemon-url", default=DEFAULT_DAEMON_URL)
    p.add_argument("--auth-token", default=os.environ.get("CORECRUXD_AUTH_TOKEN"))
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("--watch", action="store_true", help="poll continuously")
    p.add_argument("--poll-seconds", type=float, default=DEFAULT_POLL_SECONDS)
    p.add_argument("--include-archived", action="store_true", help="also tail archived sessions")
    p.add_argument("--since", default=None, help="ignore events before this RFC3339 / YYYY-MM-DD date")
    p.add_argument("--print-only", action="store_true", help="print observations to stdout instead of POSTing")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    codex_root = Path(args.codex_root).expanduser()
    cursor_path = Path(args.cursor_path).expanduser()
    cursor = load_cursor(cursor_path)
    emitter = Emitter(
        daemon_url=args.daemon_url,
        auth_token=args.auth_token,
        timeout=args.timeout,
        print_only=args.print_only,
    )
    since_ts: float | None = None
    if args.since:
        since_ts = _parse_ts(args.since) or _parse_ts(args.since + "T00:00:00Z")
        if since_ts is None:
            print(f"could not parse --since={args.since}", file=sys.stderr)
            return 2

    stop = {"now": False}

    def _stop(*_):
        stop["now"] = True

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    session_id_cache: dict[str, str] = {}

    def one_pass() -> int:
        files = discover_rollout_files(codex_root, args.include_archived)
        total = 0
        for path in files:
            total += tail_file(path, cursor, emitter, session_id_cache=session_id_cache, since_ts=since_ts)
        if total or args.watch is False:
            save_cursor(cursor_path, cursor)
        return total

    total = one_pass()
    print(
        f"[codex-tailer] pass 1: emitted={total} sent={emitter.sent} failed={emitter.failed}",
        file=sys.stderr,
    )
    if not args.watch:
        return 0 if emitter.failed == 0 else 1

    while not stop["now"]:
        time.sleep(args.poll_seconds)
        n = one_pass()
        if n:
            print(
                f"[codex-tailer] +{n} (sent={emitter.sent} failed={emitter.failed})",
                file=sys.stderr,
            )

    print(
        f"[codex-tailer] stopped. total sent={emitter.sent} failed={emitter.failed}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
