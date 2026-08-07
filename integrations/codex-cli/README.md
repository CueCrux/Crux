# Crux Daemon ⇆ Codex CLI

First-party Codex CLI adapters for Crux Daemon:

- `hooks/crux-session-start.py` injects a Crux boot banner when a Codex
  session starts.
- `crux-mcp-stdio.py` exposes Crux MCP tools to the Codex model through
  Codex's stdio MCP server config.
- `codex-tailer.py` watches Codex session JSONL files and stores observations
  in Crux.

## Startup banner hook

The startup hook prefers the shared `~/.local/bin/crux-boot-banner` used by
the other first-party agent integrations. It resolves the Codex/OpenAI agent
token at runtime, exports it to the shared banner process, and emits Codex
`hookSpecificOutput.additionalContext`. If the shared banner is not installed,
the script falls back to a compact local banner that calls the Crux MCP
endpoint for `sync_status`, `update_status`, `get_agent_identity`,
`get_passport`, and `get_bootstrap(topic="patterns", token_budget=500)`.

The hook is installed for `SessionStart` and `UserPromptSubmit`; the second
event is a first-prompt fallback for Codex hosts that do not fire
`SessionStart`. The script deduplicates by session id.

### Install

Copy the hook to a stable path:

```bash
sudo mkdir -p /usr/local/share/crux/integrations/codex-cli/hooks
sudo install -m 0755 \
  hooks/crux-session-start.py \
  /usr/local/share/crux/integrations/codex-cli/hooks/crux-session-start.py
```

Merge `hooks.snippet.json` into `~/.codex/hooks.json`, then enable Codex
hooks in `~/.codex/config.toml`:

```toml
[features]
hooks = true
```

The snippet sets `CRUX_CODEX_AGENT_NAME=openai` so the hook reads the named
token from `~/.config/cuecrux/crux-tokens/MCP_AGENT_TOKENS_CSV` at runtime.
No token is stored in `hooks.json`. Override with:

| Env var | Default | Purpose |
| --- | --- | --- |
| `CRUX_MCP_URL` | `~/.config/cuecrux/env` or `http://127.0.0.1:14801/mcp` | MCP endpoint. |
| `CRUX_CODEX_AGENT_NAME` | unset | Named agent token to read from `CRUX_AGENT_TOKENS` or the token CSV. |
| `CRUX_AGENT_TOKEN` | unset | Direct bearer token fallback. |
| `CRUX_AGENT_TOKENS_FILE` | `~/.config/cuecrux/crux-tokens/MCP_AGENT_TOKENS_CSV` | Named token CSV path. |
| `CRUX_CODEX_HOOK_TIMEOUT` | `2.0` | Per-MCP-call timeout, clamped to 0.2-10s. |
| `CRUX_CONSOLE_BASE` | unset or `~/.config/cuecrux/env` | Optional console link base passed to the shared banner. |

### Verify

```bash
CRUX_CODEX_AGENT_NAME=openai \
python3 hooks/crux-session-start.py <<'JSON' | jq .
{"hook_event_name":"SessionStart","session_id":"smoke"}
JSON

CRUX_CODEX_AGENT_NAME=openai \
python3 hooks/crux-session-start.py <<'JSON' | jq .
{"hook_event_name":"UserPromptSubmit","session_id":"smoke-prompt","prompt":"hello"}
JSON
```

The hook is fail-open. If the daemon or token is unavailable it logs to
`~/.codex/hooks/crux-session-start.errors.log` and exits 0.

Codex may require you to trust newly installed hooks in its Hooks settings UI
before they run automatically.

## In-session MCP tools

Codex must see Crux tools through an MCP server named `crux` before the model
can call tools such as `sync_status`, `get_bootstrap`, `store_fact`,
`query_facts`, and `cuecrux_session` directly.

### One command

```bash
corecruxctl start --agent codex
```

Installs the stdio bridge to `~/.codex/crux-mcp-stdio.py` and merges
`[mcp_servers.crux]` into `~/.codex/config.toml`, on top of everything plain
`corecruxctl start` already does. It is a merge, not an overwrite — your other
`mcp_servers` entries and unrelated keys survive — and it is idempotent. No
bearer material is written to `config.toml`.

Restart Codex afterwards. The manual equivalent is below, if you would rather
wire it yourself or need a non-default path.

### Manual

Codex streamable HTTP MCP support may work with newer Codex releases, but
Codex CLI `0.137.0-alpha.4` failed the Crux daemon handshake with native HTTP
and with `mcp-remote`. The supported compatibility path is the stdio bridge:

```bash
install -m 0755 crux-mcp-stdio.py ~/.codex/crux-mcp-stdio.py
```

Add this to `~/.codex/config.toml`:

```toml
[mcp_servers.crux]
command = "bash"
args = ["-lc", "exec python3 \"$HOME/.codex/crux-mcp-stdio.py\""]
```

Keep bearer material out of `config.toml`. The bridge resolves auth in this
order:

1. `CRUX_AGENT_TOKEN`
2. `CRUX_CODEX_AGENT_NAME` from `CRUX_AGENT_TOKENS`
3. `CRUX_CODEX_AGENT_NAME` from `~/.config/cuecrux/crux-tokens/MCP_AGENT_TOKENS_CSV`
4. fallback agent name `openai`

Endpoint discovery is similarly ordered:

1. `CRUX_MCP_URLS` comma- or semicolon-separated candidates
2. `CRUX_MCP_URL`
3. `CRUX_MCP_URL` in `~/.config/cuecrux/env`
4. `http://127.0.0.1:14801/mcp`

Use localhost when Codex and the daemon run on the same host. Use the
Tailscale MagicDNS name or tailnet IP when Codex connects to another node.
Use an HTTPS reverse proxy only when the daemon is intentionally exposed
outside the tailnet. In every case, set the endpoint through env or
`~/.config/cuecrux/env`, never by embedding a bearer token in the URL.

### Verify model-visible tools

```bash
codex mcp get crux

codex exec --json --disable hooks --skip-git-repo-check \
  --sandbox danger-full-access \
  'Use the crux MCP tool sync_status and report only local_only.'
```

The JSON stream should include an `mcp_tool_call` item with
`server:"crux"` and `tool:"sync_status"`.

## JSONL observation tailer

First-party adapter that watches the per-session JSONL files OpenAI's Codex
CLI writes (`~/.codex/sessions/YYYY/MM/rollout-*.jsonl`) and POSTs each new
event to a running Crux Daemon as an Ed25519-signed observation.

This is a single Python file plus a cursor JSON. No daemon plugin, no
Codex modification, no extra dependencies beyond Python 3.10+ stdlib.

## How it works

```
┌──────────────────────────────────┐  tail   ┌──────────────────────┐  POST  ┌──────────────┐
│ ~/.codex/sessions/<Y>/<M>/       │ ─────►  │ codex-tailer.py      │ ─────► │ corecruxd    │
│   rollout-<TIMESTAMP>-<UUID>.jsonl│ cursor  │ (per-file byte offset) │ HTTP  │ :14800       │
└──────────────────────────────────┘         └──────────────────────┘        │ Ed25519 sign │
                                                                              │ +append JSONL│
                                                                              └──────────────┘
```

The session UUID comes from the first line of every rollout file
(`{type:"session_meta", payload:{id:"<uuid>", ...}}`). The tailer uses
that UUID as the corecruxd session id, so all events from one Codex
conversation land in one observations file on the daemon side.

## Run

One-shot (drain everything since the last cursor, then exit):

```bash
python3 codex-tailer.py
```

Long-running (poll every 2s, watch new sessions as they appear):

```bash
python3 codex-tailer.py --watch
```

Backfill from a specific date:

```bash
python3 codex-tailer.py --since 2026-05-01 --include-archived
```

Debug (print observations instead of POSTing):

```bash
python3 codex-tailer.py --print-only
```

## Configuration

| Flag / env var                  | Default                      | Purpose                                                          |
| ------------------------------- | ---------------------------- | ---------------------------------------------------------------- |
| `--codex-root` / `CODEX_ROOT`   | `~/.codex`                   | Codex CLI root directory.                                        |
| `--cursor-path`                 | `~/.codex/.crux-tailer-cursor.json` | Per-file byte-offset cursor JSON.                          |
| `--daemon-url` / `CORECRUXD_URL`| `http://127.0.0.1:14800`     | Crux Daemon base URL.                                            |
| `--auth-token` / `CORECRUXD_AUTH_TOKEN` | _unset_              | Bearer token, only required if daemon `auth_mode` is not `off`.  |
| `--timeout` / `CRUX_OBSERVE_TIMEOUT` | `1.0`                   | Per-POST timeout (seconds).                                       |
| `--poll-seconds` / `CRUX_TAILER_POLL_SECONDS` | `2.0`            | Watch-mode poll interval.                                         |
| `--watch`                       | _off_                        | Long-running poll loop (Ctrl-C / SIGTERM to stop).               |
| `--include-archived`            | _off_                        | Also tail `~/.codex/archived_sessions/`.                          |
| `--since`                       | _none_                       | RFC3339 / YYYY-MM-DD; ignore events before this timestamp.        |
| `--print-only`                  | _off_                        | Don't POST — print observations to stdout. Useful for debugging.  |

## Failure mode

The tailer is conservative: the cursor only advances *after* a successful
POST. A daemon outage parks the cursor and the next pass retries from
the same offset, so no event is lost. Errors are logged to stderr; the
process keeps running.

If the cursor file is removed or corrupted, the tailer rebuilds it from
zero (resends all events to corecruxd from the start of every rollout
file). The daemon writes idempotently per `observation_id`, so duplicates
are tolerable but undesirable — keep the cursor file safe.

## Running as a service

systemd user service example (`~/.config/systemd/user/crux-codex-tailer.service`):

```ini
[Unit]
Description=Crux Daemon ⇆ Codex CLI tailer

[Service]
ExecStart=/usr/bin/python3 /usr/local/share/crux/integrations/codex-cli/codex-tailer.py --watch
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now crux-codex-tailer.service
journalctl --user -u crux-codex-tailer.service -f
```

## What the daemon stores

The full Codex rollout JSON line is passed through as the observation's
`payload.raw` (truncated to ≤240KB to fit the daemon's per-observation
cap). The conventional fields populated:

| Field                | Source                                              |
| -------------------- | --------------------------------------------------- |
| `provider`           | `codex-cli`                                         |
| `kind`               | `session_start` / `tool_use` / `model_response` / `codex_event` (mapped from Codex's `type`) |
| `client_ts`          | `timestamp` from the Codex line                     |
| `payload.codex_event_type` | Codex's `type` field, preserved verbatim     |
| `payload.source_file`| Absolute path of the rollout JSONL on disk          |
| `payload.raw`        | The entire Codex event JSON                         |

This means:

- We don't lose any detail Codex provides today.
- We don't break when Codex CLI updates its schema (the raw event survives).
- The daemon's signed receipt covers the full Codex line — an auditor can replay it.

## Verifying receipts

Same as for any other observation:

```bash
cargo run --example verify_observations -- \
  --jsonl "$(corecruxctl config get data_dir)/observations/<codex-session-uuid>.jsonl" \
  --pubkey-hex "$(corecruxctl config get passport.public_key_hex)"
```

## Limitations (M5-cheapest-slice)

- Polling, not inotify/fanotify. Latency = `--poll-seconds`.
- No de-duplication if you delete the cursor file (the daemon accepts duplicates).
- Doesn't follow file renames (Codex doesn't rename rollouts, so fine in practice).
- `--include-archived` is opt-in to avoid double-emitting events you already saw in `sessions/`.
