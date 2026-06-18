# Crux Daemon ⇆ Claude Code observation hooks

First-party adapter that captures every Claude Code lifecycle event
(SessionStart / UserPromptSubmit / PostToolUse / Stop / SessionEnd) and
posts it to a running Crux Daemon. Each observation is Ed25519-signed by
the daemon so the resulting log is **verifiable evidence**, not a
self-reported file.

This is a single bash hook script plus a `settings.json` snippet. No
plugin, no MCP server, no extra dependencies beyond `curl` and `jq`.

## How it works

```
┌────────────────┐  stdin   ┌─────────────────────┐  POST    ┌──────────────┐
│ Claude Code    │ ───────► │ crux-observe.sh      │ ───────► │ corecruxd    │
│ hook event     │  JSON    │ (this adapter)       │ HTTP     │ :14800       │
└────────────────┘          └─────────────────────┘          │ Ed25519 sign │
                                                              │ +append JSONL│
                                                              └──────────────┘
```

The daemon writes one JSONL file per session at
`<data_dir>/observations/<scoped_session_id>.jsonl`. Each line carries a
`receipt` field (`alg=ed25519`, `signed_by=<passport_fpr>`,
`body_hash=blake3:…`, `signature=<hex>`) that verifies against the
daemon's published passport public key.

## Install (recommended: `corecruxctl hooks install`)

`corecruxctl hooks install` installs the launcher + observe script under
`~/.local/share/crux/hooks/`, merges the hooks block into your settings, and
**captures the daemon endpoint** the hooks read at runtime:

```bash
# Point the hooks at a daemon and wire them up in one step.
corecruxctl hooks install --user --endpoint crux-host:14800
# Omit --endpoint to be prompted (interactive), or to keep an already-saved one.
```

The endpoint is saved to `~/.config/cuecrux/env` (0600) as `CRUX_HTTP_URL` +
the derived `CRUX_MCP_URL`; the launcher (`crux-hook-env.sh`) sources that file
so the URL and bearer token never live in `settings.json`. Re-run with a new
`--endpoint` to repoint (e.g. when moving from localhost to a Tailscale host).
`corecruxctl login --url <daemon>` writes the same file and additionally mints
the auth token.

## Install (manual)

1. Copy the hook script somewhere stable on disk. The snippet assumes
   `/usr/local/share/crux/integrations/claude-code/`, but anywhere works
   — just update the `command` paths to match.

   ```bash
   sudo install -D -m 0755 \
     hooks/crux-observe.sh \
     /usr/local/share/crux/integrations/claude-code/hooks/crux-observe.sh
   ```

2. Merge the `hooks` block from `settings.snippet.json` into your
   `~/.claude/settings.json`. (If your file already has a `hooks` block,
   merge per-event rather than overwriting.)

3. Make sure `corecruxd` is running. The default URL is
   `http://127.0.0.1:14800`; override with `CORECRUXD_URL` if you've
   bound to a different port.

4. Start a Claude Code session. Watch observations land:

   ```bash
   tail -f "$(corecruxctl config get data_dir)/observations/"*.jsonl
   ```

## Configuration (environment)

| Variable                  | Default                  | Purpose                                                              |
| ------------------------- | ------------------------ | -------------------------------------------------------------------- |
| `CORECRUXD_URL`           | `http://127.0.0.1:14800` | Daemon base URL.                                                     |
| `CORECRUXD_AUTH_TOKEN`    | _unset_                  | Bearer token, only required if daemon `auth_mode` is not `off`.      |
| `CRUX_OBSERVE_TIMEOUT`    | `0.5`                    | curl `--max-time` in seconds. The hook is fire-and-forget; keep low. |
| `CRUX_OBSERVE_MAX_FIELD_CHARS` | `16384`             | Per string-field truncation cap. Longer strings are cut with a `…[crux-truncated N chars]` marker. |
| `CRUX_OBSERVE_MAX_BODY_BYTES`  | `262144`            | Whole-body cap. If field truncation still leaves the body over this, the payload is replaced with a compact stub (event still recorded). Keep ≤ the daemon's payload cap. |

The daemon caps each observation's `payload` at
`CORECRUXD_MAX_OBSERVATION_PAYLOAD_BYTES` (default 1 MiB) and returns `413`
above it. The hook's two size guards keep payloads under that cap so large tool
I/O is captured *truncated* rather than dropped; raise both sides together if
you want larger observations retained.

When installed via `corecruxctl hooks install`, the launcher sources
`~/.config/cuecrux/env` and maps `CRUX_HTTP_URL` → `CORECRUXD_URL` and
`CRUX_AGENT_TOKEN` → `CORECRUXD_AUTH_TOKEN`, so you configure the endpoint once
in that file rather than per-variable here.

## Failure mode

Every failure path exits `0`. Errors land in
`~/.claude/hooks/crux-observe.errors.log` for diagnosis. The Claude Code
session is never blocked by daemon outage, missing binaries, network
issues, or schema drift.

## Verifying receipts

For every observation in the JSONL file, you can independently verify
the signature against the daemon's public key:

```bash
# Extract the daemon's published passport public key (32 bytes hex)
DAEMON_PUBKEY="$(cat "$(corecruxctl config get data_dir)/passport.key" | xxd -r -p | openssl pkey -inform raw -pubout -outform raw 2>/dev/null | xxd -p)"

# Or: run the daemon and read AppState.passport_public_key_hex via
#   curl -s http://127.0.0.1:14800/v1/console/whoami | jq -r .public_key_hex

cargo run --example verify_observations -- \
  --jsonl "$(corecruxctl config get data_dir)/observations/<session>.jsonl" \
  --pubkey-hex "${DAEMON_PUBKEY}"
```

The verifier uses only `serde_json` + `blake3` + `ed25519-dalek` (no daemon
state, no network), so an auditor with the JSONL file and the published
public key can validate any session offline.

A smoke test that exercises the full sign→write→verify→tamper-detect
chain is at `Crux/scripts/smoke-observations.sh`.

## What the daemon stores

The full Claude Code hook payload is passed through as the
observation's `payload` field — no schema translation. This means:

- We don't lose any detail the hook contract provides today.
- We don't break when Anthropic adds new hook fields.
- We don't need to update this adapter when Claude Code evolves.

The cost is that the payload is opaque to retrieval. M5+ of the ExecPlan
adds MCP search/timeline tools that parse the conventional fields.

## Comparison vs claude-mem

`claude-mem` (npm) uses the same hook surface to capture observations
into a local SQLite + ChromaDB, then injects compressed context at
SessionStart. It's a productivity plugin: very good at IDE stickiness,
no cryptographic provenance.

This adapter does **less of the productivity story** but every line in
the JSONL has a verifiable Ed25519 signature. The two are not mutually
exclusive — you can run both.
