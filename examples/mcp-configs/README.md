# MCP Client Configuration Examples

Example configuration files for connecting MCP clients to a running Crux Daemon instance.

## How it works

For MCP clients, the relevant network surfaces are:

| Port | Protocol | Purpose |
|------|----------|---------|
| **14800** | HTTP/REST | Human-facing API (`/healthz`, `/v1/facts`, `/v1/query/*`) |
| **14801** | MCP (JSON-RPC) | Agent-facing API with token-filtered tools for retrieval, facts, sessions, sync, updates, and decisions |

Your MCP client connects to `http://localhost:14801/mcp`.

## Prerequisites

1. Crux Daemon must be running:

   ```bash
   docker compose up -d
   # or: source config.example.env && ./corecruxd
   ```

2. Verify the MCP server is reachable:

   ```bash
   curl -s -X POST http://localhost:14801/mcp \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}' \
     | jq '.result.tools[].name'
   # Expected output includes query, store_fact, query_facts, and cuecrux_session
   ```

If the server is configured with `CRUX_AGENT_TOKEN` or `CRUX_AGENT_TOKENS`,
send the matching `Authorization: Bearer <token>` header on MCP requests.
If you rely on handoff packages across restarts or multiple replicas, configure
the same `CRUX_MCP_HANDOFF_SECRET` on every instance.

## Claude Desktop

**Preferred: install the bundle from the console.** Open the console
(`localhost:14800`) → the account badge → **Connections**, and download
`crux.mcpb`. Drag it onto Claude Desktop's Settings → Extensions pane. Desktop
prompts for the two values it needs — the MCP endpoint URL and the agent token —
so there is no config file to hand-edit.

The URL field defaults to `http://127.0.0.1:14801/mcp`, which is right when
Desktop and the daemon share a machine. Point it at your own host when they do
not — `http://<host-or-tailnet-ip>:14801/mcp` on a private network, or
`https://<your-host>/mcp` if a TLS proxy fronts the daemon (the MCP port is
usually not exposed directly). Note that Desktop runs on the Windows side of
WSL, so a daemon inside WSL is *not* on Desktop's localhost.

That page also reports the endpoint URLs and the agent-token state. The token's
raw value is shown only when the daemon sets
`CORECRUXD_CONSOLE_REVEAL_AGENT_TOKEN=1`; otherwise you get a fingerprint and
length, enough to confirm you are holding the right credential. Paste the raw
token into Desktop — the `Bearer ` prefix is added for you. Leave the field
blank if the daemon runs without token auth.

The bundle is unsigned. Desktop accepts it today; a future Desktop policy may
require signatures.

### Hand-editing the config instead

The config file lives at:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/claude/claude_desktop_config.json`

On **macOS and Linux**, merge `claude-desktop.json`'s `mcpServers` object into
that file.

On **Windows this does not work.** Claude Desktop rejects the native
`{"url": ...}` shape there — it reports the entry as "not valid MCP server
configurations and were skipped" and accepts only stdio-transport servers. Use
the `mcp-remote` shim:

```json
{
  "mcpServers": {
    "crux": {
      "command": "C:\\Users\\<you>\\AppData\\Roaming\\npm\\mcp-remote.cmd",
      "args": [
        "https://crux.example.com/mcp",
        "--transport", "http-only",
        "--allow-http",
        "--header", "Authorization:${CRUX_AUTH_HEADER}"
      ],
      "env": { "CRUX_AUTH_HEADER": "Bearer <CRUX_AGENT_TOKEN>" }
    }
  }
}
```

Three things that bite, in order:

1. **Install `mcp-remote` globally** (`npm install -g mcp-remote`) and use the
   full `.cmd` path. Setting `"command": "npx"` resolves to
   `C:\Program Files\nodejs\npx.cmd`; Desktop wraps commands in `cmd /C` without
   quoting, so `C:\Program` is parsed as the program name and the server dies.
2. **The token goes in `env`, not inline in the header arg.** Desktop strips
   spaces in args, which would mangle `Bearer <token>`. `mcp-remote` expands
   `${VAR}` inside `--header` values, so the space survives in the environment.
   This also keeps the secret out of the process argv.
3. **`--allow-http`** is required for a plain-HTTP endpoint that is not
   localhost (a tailnet daemon). Harmless on HTTPS.

Read `%APPDATA%\Claude\logs\mcp*.log` after each restart — the args array is
logged verbatim on startup, so a misconfiguration is visible immediately.

## Claude Code

Add to your project's `.claude/settings.json`:

```json
{
  "mcpServers": {
    "crux": {
      "url": "http://localhost:14801/mcp"
    }
  }
}
```

## Cursor

Copy `cursor.json` into your project root as `.cursor/mcp.json`, or merge the
`mcpServers` object into your existing Cursor MCP configuration.

## Custom Port

If Crux Daemon is running on a different MCP port, update the `url` field:

```json
{
  "mcpServers": {
    "crux": {
      "url": "http://localhost:<your-mcp-port>/mcp"
    }
  }
}
```

## After connecting

Your agent's first 3 calls should be:

1. `get_bootstrap("patterns")` — learn optimal usage patterns
2. `store_fact(entity="test", key="hello", value="world")` — store a fact
3. `query_facts(query="hello")` — retrieve it

Before maintenance work, call `update_status()` and pull
`get_bootstrap(topic="docs", query="upgrade")` plus
`get_bootstrap(topic="docs", query="backup")`.

See `docs/agent-guide.md` for the full integration guide.
