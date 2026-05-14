# Crux Daemon ⇆ Codex CLI tailer

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
