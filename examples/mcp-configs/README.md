# MCP Client Configuration Examples

Example configuration files for connecting MCP clients to a running CoreCrux instance.

## How it works

For MCP clients, the relevant network surfaces are:

| Port | Protocol | Purpose |
|------|----------|---------|
| **14800** | HTTP/REST | Human-facing API (`/healthz`, `/v1/facts`, `/v1/query/*`) |
| **14801** | MCP (JSON-RPC) | Agent-facing API (21 tools for retrieval, facts, sessions, sync, decisions) |

Your MCP client connects to `http://localhost:14801/mcp`.

## Prerequisites

1. CoreCrux must be running:
   ```bash
   docker compose up -d
   # or: source config.example.env && ./corecruxd
   ```

2. Verify the MCP server is reachable:
   ```bash
   curl -s -X POST http://localhost:14801/mcp \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}' | jq '.result.tools | length'
   # Expected output: 21
   ```

If the server is configured with `CRUX_AGENT_TOKEN` or `CRUX_AGENT_TOKENS`,
send the matching `Authorization: Bearer <token>` header on MCP requests.
If you rely on handoff packages across restarts or multiple replicas, configure
the same `CRUX_MCP_HANDOFF_SECRET` on every instance.

## Claude Desktop

Copy `claude-desktop.json` into your Claude Desktop configuration:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/claude/claude_desktop_config.json`

Merge the `mcpServers` object with any existing servers in your config.

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

If CoreCrux is running on a different MCP port, update the `url` field:

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

See `docs/agent-guide.md` for the full integration guide.
