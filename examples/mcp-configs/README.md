# MCP Client Configuration Examples

Example configuration files for connecting MCP clients to a running CoreCrux instance.

## Prerequisites

CoreCrux must be running with the MCP server enabled (default port 14801).

```bash
cargo run --release -p corecruxd
```

## Claude Desktop

Copy `claude-desktop.json` into your Claude Desktop configuration:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/claude/claude_desktop_config.json`

Merge the `mcpServers` object with any existing servers in your config.

## Cursor

Copy `cursor.json` into your project root as `.cursor/mcp.json`, or merge the
`mcpServers` object into your existing Cursor MCP configuration.

## Custom Port

If CoreCrux is running on a different port, update the `url` field accordingly:

```json
{
  "mcpServers": {
    "crux": {
      "url": "http://localhost:<your-port>/mcp"
    }
  }
}
```
