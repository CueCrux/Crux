# Crux Daemon ⇆ Codex CLI

First-party Codex CLI adapters for Crux Daemon:

- `hooks/crux-session-start.py` injects a Crux boot banner when a Codex
  session starts.
- `crux-hook observe-pre`, reached through the release enforcement wrapper,
  denies native `apply_patch` calls that overlap an enforced punchcard.
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

The snippet preserves a process-level `CRUX_CODEX_AGENT_NAME` and defaults to
`openai` only when it is unset, so the hook reads the selected named token at
runtime. No token is stored in `hooks.json`. Override with:

| Env var | Default | Purpose |
| --- | --- | --- |
| `CRUX_MCP_URL` | `~/.config/cuecrux/env` or `http://127.0.0.1:14801/mcp` | MCP endpoint. |
| `CRUX_CODEX_AGENT_NAME` | unset | Agent label/token selector; valid values are 1-64 ASCII letters, digits, `.`, `_`, or `-`. |
| `CRUX_AGENT_TOKEN` | unset | Per-process bearer token; highest precedence in every Codex adapter. |
| `CRUX_AGENT_TOKENS_FILE` | `~/.config/cuecrux/crux-tokens/MCP_AGENT_TOKENS_CSV` | Named token CSV path. |
| `CRUX_AGENT_TOKEN_DIR` | `~/.config/cuecrux/crux-tokens` | Named `*.mcp-token` directory used by the enforcement wrapper. |
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

## Native `apply_patch` enforcement

`hooks.snippet.json` contains one synchronous `PreToolUse` entry with matcher
`^apply_patch$` and a 15-second outer timeout. It invokes the accepted
release's stable wrapper:

```text
$HOME/.local/share/crux/hooks/crux-enforce.sh
```

Install the tracked wrapper as mode `0700` during the verified release rollout:

```bash
install -d -m 0700 "$HOME/.local/share/crux/hooks"
install -m 0700 hooks/crux-enforce.sh \
  "$HOME/.local/share/crux/hooks/crux-enforce.sh"
```

It sources the existing mode-`0600` CueCrux environment and then `exec`s
`$HOME/.local/bin/crux-hook observe-pre`. A process-level `CRUX_AGENT_TOKEN`
takes precedence; otherwise it reads only
`$CRUX_AGENT_TOKEN_DIR/${CRUX_CODEX_AGENT_NAME:-openai}.mcp-token`. Do not copy
a bearer token into the wrapper or `hooks.json`, and do not point the wrapper
at a mutable checkout. Merge the snippet only after that path resolves to the
accepted release binary, then review/trust the command in Codex's Hooks
settings.

### Concurrent-writer identity

Punchcards distinguish holders by the passport authenticated by the hook's
bearer token, not by Codex's `session_id`. Every concurrent Codex writer must
therefore run with a distinct process-injected token/passport and a distinct
`CRUX_CODEX_AGENT_NAME`. Fleet mode additionally requires
`CORECRUXD_AGENT_PASSPORTS=1` and one explicit, distinct
`CRUX_AGENT_PASSPORTS=<agent>:<passport>:<tenant>` entry per worker, for
example `worker-a:codex-worker-a:work,worker-b:codex-worker-b:work`. An
unmapped token authenticates punchcard checks as `agent:<name>`, while its raw
`get_passport` key may be only `<name>`; those identities are not equivalent.

Before acquiring a lease, require `auth_posture_audit` to report agent
passports enabled and require `get_passport` to name the worker's explicitly
mapped passport. Use that configured passport as the exact punchcard holder.
The fleet launcher must reject a disabled mapping flag, an unmapped worker, or
a missing, duplicate, or mismatched identity before creating a worktree or
acquiring a lease. Sessions sharing the fallback `openai` token see each
other's cards as self-held and are not isolated; auth-off or shared-anonymous
mode cannot provide fleet isolation.

The enforcement gate uses two Codex processes with distinct synthetic-safe
credentials: worker A holds an absolute file lease, A's hook reports no peer
conflict, and worker B's hook denies the same patch without mutating the file.
Releasing A's lease then permits B. Never print either credential while
running this gate. Until the mapping checks and live two-worker gate pass, this
source integration is cross-passport enforcement infrastructure, not Program
3/4 fleet-M2 closure.

For each canonical patch, the hook parses every Add, Update, Delete, and Move
source/destination, normalizes those paths below the hook `cwd` to one absolute
lexical spelling, and checks every `file://<absolute-path>` punchcard resource.
A malformed or escaping patch is denied. Manual and fleet leases intended to
cover these edits must use the same absolute namespace (`file:///absolute/path`
or an enclosing `tree:///absolute/directory`); repo-relative resources are not
aliases and can be ambiguous across worktrees.
Any enforced conflict denies the whole patch and names all conflicts. A valid
conflict-free patch emits zero stdout bytes, which is Codex's supported
no-decision path; daemon transport failures retain the existing fail-open
policy.

Check the source integration before installing it:

```bash
jq empty hooks.snippet.json

tmp_dir="$(mktemp -d)"
printf '%s' "{\"hook_event_name\":\"PreToolUse\",\"session_id\":\"smoke\",\"transcript_path\":null,\"cwd\":\"$tmp_dir\",\"tool_name\":\"apply_patch\",\"tool_input\":{\"command\":\"*** Begin Patch\\n*** Add File: smoke.txt\\n+ok\\n*** End Patch\"}}" \
  | CRUX_MCP_URL=http://127.0.0.1:1/mcp crux-hook observe-pre
```

The second command exits zero with no stdout when the daemon is unavailable.
The release gate additionally requires the two-Codex, distinct-passport test
above: the holder's own probe is conflict-free, the other passport's patch is
denied and the file hash is unchanged, and the same patch proceeds only after
release. Ensure the effective Codex configuration contains exactly one
`observe-pre` enforcement command and no two active workers resolve to the
same passport.

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
