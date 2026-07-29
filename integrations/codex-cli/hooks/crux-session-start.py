#!/usr/bin/env python3
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# Codex SessionStart hook -> Crux Daemon boot banner.
#
# Reads the Codex hook event JSON on stdin, calls the Crux MCP endpoint for
# boot context, and emits Codex hookSpecificOutput.additionalContext. Best
# effort: daemon/auth failures are logged and the hook exits 0.

from __future__ import annotations

import csv
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_MCP_URL = "http://127.0.0.1:14801/mcp"
DEFAULT_TOKEN_FILE = "~/.config/cuecrux/crux-tokens/MCP_AGENT_TOKENS_CSV"
DEFAULT_ENV_FILE = "~/.config/cuecrux/env"
DEFAULT_TIMEOUT = 2.0
BOOTSTRAP_TOKEN_BUDGET = 500
MAX_BOOTSTRAP_CHARS = 2200
SEEN_FILE = "~/.codex/hooks/crux-session-banner.seen.json"


def main() -> int:
    hook_input = _consume_stdin()
    hook_event_name = output_hook_event_name(hook_input)

    if os.environ.get("CRUX_CODEX_SESSION_START", "").lower() == "off":
        return 0
    if should_skip_seen_session(hook_input, hook_event_name):
        return 0

    # Prefer the shared Crux banner used by Claude and other first-party
    # agents. It emits Codex-compatible hookSpecificOutput JSON and keeps the
    # rich boot table in one implementation.
    banner = os.path.expanduser("~/.local/bin/crux-boot-banner")
    if os.access(banner, os.X_OK):
        env = os.environ.copy()
        env["CRUX_MCP_URL"] = mcp_url()
        tok = resolve_token()
        if tok:
            env["CRUX_AGENT_TOKEN"] = tok
        if not env.get("CRUX_CONSOLE_BASE"):
            console = read_env_file_value(
                Path(os.path.expanduser(DEFAULT_ENV_FILE)), "CRUX_CONSOLE_BASE"
            )
            if console:
                env["CRUX_CONSOLE_BASE"] = console
        mark_session_seen(hook_input)
        try:
            os.execve(banner, [banner], env)
        except OSError as err:
            log_error(f"exec crux-boot-banner failed: {err}")

    # Legacy fallback: compact daemon-only banner for hosts that have not
    # installed the shared banner binary yet.
    try:
        client = McpClient(mcp_url(), token=resolve_token(), timeout=timeout_seconds())
        sections = build_sections(client)
    except Exception as err:  # noqa: BLE001 - hooks must fail open.
        log_error(f"session-start failed: {err}")
        return 0

    if sections:
        emit_context("\n\n".join(sections), hook_event_name)
        mark_session_seen(hook_input)
    return 0


class McpClient:
    def __init__(self, url: str, *, token: str | None, timeout: float) -> None:
        self.url = url
        self.token = token
        self.timeout = timeout
        self.next_id = 1

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        envelope = {
            "jsonrpc": "2.0",
            "id": self.next_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
        self.next_id += 1
        data = json.dumps(envelope).encode("utf-8")
        req = urllib.request.Request(
            self.url,
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        if body.get("error"):
            raise RuntimeError(f"{name}: {json.dumps(body['error'], sort_keys=True)}")
        result = body.get("result")
        if not isinstance(result, dict):
            raise RuntimeError(f"{name}: missing result")
        return result


def build_sections(client: McpClient) -> list[str]:
    sections: list[str] = []

    identity_text = safe_tool_text(client, "get_agent_identity", {})
    identity = identity_text.strip() or "unknown"

    sync = safe_tool_result(client, "sync_status", {})
    update = safe_tool_result(client, "update_status", {})
    passport_text = safe_tool_text(client, "get_passport", {})
    bootstrap_text = safe_tool_text(
        client,
        "get_bootstrap",
        {"topic": "patterns", "token_budget": BOOTSTRAP_TOKEN_BUDGET},
    )

    banner_lines = [
        "Crux Banner",
        f"- Agent identity: {identity}",
        f"- MCP: {redact_url(client.url)}",
    ]
    if sync is not None:
        banner_lines.append(f"- Sync: {summarize_sync(sync)}")
    if update is not None:
        banner_lines.append(f"- Update: {summarize_update(update)}")
    if passport_text:
        banner_lines.append(f"- Passport: {one_line(passport_text, 260)}")
    sections.append("\n".join(banner_lines))

    if bootstrap_text:
        sections.append("Crux bootstrap (patterns)\n" + cap_text(bootstrap_text, MAX_BOOTSTRAP_CHARS))

    return sections


def safe_tool_result(client: McpClient, name: str, args: dict[str, Any]) -> dict[str, Any] | None:
    try:
        text = extract_text(client.call_tool(name, args))
    except Exception as err:  # noqa: BLE001
        log_error(f"{name} failed: {err}")
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {"text": text}
    return parsed if isinstance(parsed, dict) else {"text": text}


def safe_tool_text(client: McpClient, name: str, args: dict[str, Any]) -> str:
    try:
        return extract_text(client.call_tool(name, args))
    except Exception as err:  # noqa: BLE001
        log_error(f"{name} failed: {err}")
        return ""


def extract_text(result: dict[str, Any]) -> str:
    content = result.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                return item["text"]
    return json.dumps(result, indent=2, sort_keys=True)


def summarize_sync(sync: dict[str, Any]) -> str:
    mode = sync.get("mode", "unknown")
    degraded = sync.get("degraded", False)
    fact_count = sync.get("local_fact_count")
    configured = sync.get("configured")
    parts = [f"mode={mode}", f"degraded={str(bool(degraded)).lower()}"]
    if configured is not None:
        parts.append(f"configured={str(bool(configured)).lower()}")
    if fact_count is not None:
        parts.append(f"local_fact_count={fact_count}")
    return ", ".join(parts)


def summarize_update(update: dict[str, Any]) -> str:
    state = update.get("state", "unknown")
    current = update.get("current_commit")
    latest = update.get("latest_commit")
    behind_by = update.get("behind_by")
    ahead_by = update.get("ahead_by")
    parts = [f"state={state}"]
    if current and latest:
        parts.append(f"{current}->{latest}")
    if behind_by:
        parts.append(f"behind_by={behind_by}")
    if ahead_by:
        parts.append(f"ahead_by={ahead_by}")
    return ", ".join(parts)


def mcp_url() -> str:
    env_url = os.environ.get("CRUX_MCP_URL", "").strip()
    if env_url:
        return env_url
    file_url = read_env_file_value(Path(os.path.expanduser(DEFAULT_ENV_FILE)), "CRUX_MCP_URL")
    return file_url or DEFAULT_MCP_URL


def resolve_token() -> str | None:
    agent_name = os.environ.get("CRUX_CODEX_AGENT_NAME", "").strip()
    if agent_name:
        named = token_for_agent(agent_name)
        if named:
            return named
        log_error(f"token for CRUX_CODEX_AGENT_NAME={agent_name} not found")

    token = os.environ.get("CRUX_AGENT_TOKEN", "").strip()
    if token:
        return token

    fallback_name = os.environ.get("CRUX_AGENT_TOKEN_NAME", "").strip()
    if fallback_name:
        return token_for_agent(fallback_name)
    return None


def token_for_agent(agent_name: str) -> str | None:
    pairs = os.environ.get("CRUX_AGENT_TOKENS", "")
    token = token_for_agent_from_csv(pairs, agent_name)
    if token:
        return token
    token_file = Path(os.path.expanduser(os.environ.get("CRUX_AGENT_TOKENS_FILE", DEFAULT_TOKEN_FILE)))
    if token_file.exists():
        try:
            return token_for_agent_from_csv(token_file.read_text(encoding="utf-8"), agent_name)
        except OSError as err:
            log_error(f"failed to read token file: {err}")
    return None


def token_for_agent_from_csv(raw: str, agent_name: str) -> str | None:
    if not raw.strip():
        return None
    reader = csv.reader([raw])
    for row in reader:
        for item in row:
            name, sep, token = item.partition(":")
            if sep and name == agent_name and token:
                return token.strip()
    return None


def read_env_file_value(path: Path, key: str) -> str | None:
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            name, sep, value = stripped.partition("=")
            if sep and name == key:
                return value.strip().strip('"').strip("'")
    except OSError:
        return None
    return None


def timeout_seconds() -> float:
    raw = os.environ.get("CRUX_CODEX_HOOK_TIMEOUT", os.environ.get("CRUX_HOOK_TIMEOUT", ""))
    if not raw:
        return DEFAULT_TIMEOUT
    try:
        return max(0.2, min(float(raw), 10.0))
    except ValueError:
        return DEFAULT_TIMEOUT


def _consume_stdin() -> dict[str, Any]:
    try:
        raw = sys.stdin.read()
        return json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        return {}


def output_hook_event_name(hook_input: dict[str, Any]) -> str:
    raw = str(hook_input.get("hook_event_name") or hook_input.get("hookEventName") or "")
    normalized = raw.replace("-", "_").lower()
    if normalized in {"user_prompt_submit", "userpromptsubmit"}:
        return "UserPromptSubmit"
    return "SessionStart"


def should_skip_seen_session(hook_input: dict[str, Any], hook_event_name: str) -> bool:
    if hook_event_name != "UserPromptSubmit":
        return False
    session_id = str(hook_input.get("session_id") or "").strip()
    return bool(session_id and session_id in read_seen_sessions())


def read_seen_sessions() -> set[str]:
    path = Path(os.path.expanduser(SEEN_FILE))
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    if not isinstance(data, list):
        return set()
    return {str(item) for item in data if isinstance(item, str)}


def mark_session_seen(hook_input: dict[str, Any]) -> None:
    session_id = str(hook_input.get("session_id") or "").strip()
    if not session_id:
        return
    path = Path(os.path.expanduser(SEEN_FILE))
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        seen = read_seen_sessions()
        seen.add(session_id)
        path.write_text(json.dumps(sorted(seen)[-200:]), encoding="utf-8")
    except OSError as err:
        log_error(f"failed to update seen sessions: {err}")


def emit_context(context: str, hook_event_name: str) -> None:
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": hook_event_name,
                    "additionalContext": context,
                }
            },
            separators=(",", ":"),
        )
    )


def log_error(message: str) -> None:
    log_dir = Path.home() / ".codex" / "hooks"
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with (log_dir / "crux-session-start.errors.log").open("a", encoding="utf-8") as f:
            f.write(f"{ts} {message}\n")
    except OSError:
        pass


def one_line(text: str, limit: int) -> str:
    return cap_text(" ".join(text.split()), limit)


def cap_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)] + "..."


def redact_url(url: str) -> str:
    return url.replace("Authorization", "[redacted]")


if __name__ == "__main__":
    raise SystemExit(main())
