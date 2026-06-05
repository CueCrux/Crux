#!/usr/bin/env python3
"""Codex stdio MCP bridge for Crux Daemon HTTP MCP.

Codex stdio MCP uses newline-delimited JSON-RPC. Crux Daemon serves MCP over
HTTP. This bridge lets Codex expose Crux tools without embedding bearer tokens
in config.toml.
"""

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
DEFAULT_AGENT_NAME = "openai"
DEFAULT_TIMEOUT = 10.0
OUTPUT_FRAMING = "jsonl"


def main() -> int:
    debug_log(
        "bridge process started "
        f"pid={os.getpid()} home={Path.home()} cwd={Path.cwd()} "
        f"token_env={'yes' if os.environ.get('CRUX_AGENT_TOKEN') else 'no'}"
    )
    while True:
        msg = read_message()
        if msg is None:
            return 0
        try:
            handle_message(msg)
        except Exception as err:  # noqa: BLE001 - bridge must fail as JSON-RPC.
            log_error(f"message handling failed: {err}")
            msg_id = msg.get("id") if isinstance(msg, dict) else None
            if msg_id is not None:
                write_message(
                    {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {"code": -32000, "message": str(err)},
                    }
                )


def handle_message(msg: dict[str, Any]) -> None:
    method = str(msg.get("method") or "")
    msg_id = msg.get("id")
    if not method or method.startswith("notifications/") or msg_id is None:
        return

    if method == "initialize":
        requested_protocol = requested_protocol_version(msg)
        result = remote_initialize(requested_protocol)
        write_message(
            {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": requested_protocol
                    or result.get("protocolVersion", "2024-11-05"),
                    "capabilities": {"tools": {}},
                    "serverInfo": result.get(
                        "serverInfo", {"name": "crux-stdio-bridge", "version": "0.1.0"}
                    ),
                },
            }
        )
        return

    if method in {"tools/list", "tools/call"}:
        remote = remote_jsonrpc(method, (msg.get("params") or {}))
        if "error" in remote:
            write_message({"jsonrpc": "2.0", "id": msg_id, "error": remote["error"]})
        else:
            write_message({"jsonrpc": "2.0", "id": msg_id, "result": remote.get("result", {})})
        return

    if method == "ping":
        write_message({"jsonrpc": "2.0", "id": msg_id, "result": {}})
        return
    if method == "resources/list":
        write_message({"jsonrpc": "2.0", "id": msg_id, "result": {"resources": []}})
        return
    if method == "prompts/list":
        write_message({"jsonrpc": "2.0", "id": msg_id, "result": {"prompts": []}})
        return

    write_message(
        {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }
    )


def requested_protocol_version(msg: dict[str, Any]) -> str:
    params = msg.get("params")
    if isinstance(params, dict):
        raw = params.get("protocolVersion")
        if isinstance(raw, str) and raw:
            return raw
    return "2024-11-05"


def remote_initialize(protocol_version: str) -> dict[str, Any]:
    remote = remote_jsonrpc(
        "initialize",
        {
            "protocolVersion": protocol_version,
            "capabilities": {},
            "clientInfo": {"name": "codex-crux-stdio", "version": "0.1.0"},
        },
    )
    if "error" in remote:
        raise RuntimeError(json.dumps(remote["error"], sort_keys=True))
    result = remote.get("result")
    return result if isinstance(result, dict) else {}


def remote_jsonrpc(method: str, params: dict[str, Any]) -> dict[str, Any]:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        separators=(",", ":"),
    ).encode("utf-8")
    last_error: Exception | None = None
    for url in mcp_urls():
        req = urllib.request.Request(
            url,
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        token = resolve_token()
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=timeout_seconds()) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError:
            raise
        except Exception as err:  # noqa: BLE001
            last_error = err
            debug_log(f"{url} failed: {err}")
    raise RuntimeError(f"no Crux MCP endpoint reachable: {last_error}")


def read_message() -> dict[str, Any] | None:
    global OUTPUT_FRAMING

    headers: dict[str, str] = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        line = line.rstrip(b"\r\n")
        if not line:
            if headers:
                break
            continue
        stripped = line.lstrip()
        if stripped.startswith(b"{"):
            OUTPUT_FRAMING = "jsonl"
            parsed = json.loads(stripped.decode("utf-8"))
            return parsed if isinstance(parsed, dict) else {}
        key, sep, value = line.decode("utf-8", errors="replace").partition(":")
        if sep:
            headers[key.lower()] = value.strip()

    OUTPUT_FRAMING = "headers"
    length = int(headers.get("content-length", "0"))
    if length <= 0:
        return None
    body = sys.stdin.buffer.read(length)
    if not body:
        return None
    parsed = json.loads(body.decode("utf-8"))
    return parsed if isinstance(parsed, dict) else {}


def write_message(msg: dict[str, Any]) -> None:
    body = json.dumps(msg, separators=(",", ":")).encode("utf-8")
    if OUTPUT_FRAMING == "headers":
        sys.stdout.buffer.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii"))
        sys.stdout.buffer.write(body)
    else:
        sys.stdout.buffer.write(body + b"\n")
    sys.stdout.buffer.flush()


def mcp_urls() -> list[str]:
    urls: list[str] = []
    add_urls(urls, os.environ.get("CRUX_MCP_URLS", ""))
    add_urls(urls, os.environ.get("CRUX_MCP_URL", ""))
    file_url = read_env_file_value(Path(os.path.expanduser(DEFAULT_ENV_FILE)), "CRUX_MCP_URL")
    add_urls(urls, file_url or "")
    add_urls(urls, DEFAULT_MCP_URL)
    return urls


def add_urls(urls: list[str], raw: str) -> None:
    for item in raw.replace(";", ",").split(","):
        url = item.strip()
        if url and url not in urls:
            urls.append(url)


def resolve_token() -> str | None:
    token = os.environ.get("CRUX_AGENT_TOKEN", "").strip()
    if token:
        return token
    agent_name = os.environ.get("CRUX_CODEX_AGENT_NAME", DEFAULT_AGENT_NAME).strip()
    return token_for_agent(agent_name) if agent_name else None


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
    raw = os.environ.get("CRUX_MCP_BRIDGE_TIMEOUT", "")
    if not raw:
        return DEFAULT_TIMEOUT
    try:
        return max(0.2, min(float(raw), 30.0))
    except ValueError:
        return DEFAULT_TIMEOUT


def log_error(message: str) -> None:
    log_dir = Path.home() / ".codex" / "hooks"
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with (log_dir / "crux-mcp-stdio.errors.log").open("a", encoding="utf-8") as f:
            f.write(f"{ts} {message}\n")
    except OSError:
        pass


def debug_log(message: str) -> None:
    if os.environ.get("CRUX_MCP_BRIDGE_DEBUG", "").lower() not in {"1", "true", "yes"}:
        return
    log_error(message)


if __name__ == "__main__":
    raise SystemExit(main())
