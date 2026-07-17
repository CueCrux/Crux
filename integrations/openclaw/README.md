# OpenClaw ↔ Crux integration (ClawHub skill skeleton)

Status: **skeleton** (M13 stretch of ExecPlan `verifiable-record-products-2026-07-17`,
W3 ICP-1). Local-first and free.

Routes OpenClaw agent memory through a local [Crux](../../README.md) daemon so
every durable memory carries a tamper-evident, verifiable record — and can be
imported and scanned for MemGhost-style poisoning with `corecruxctl openclaw`.

## Contents

- [`crux-memory-custody/SKILL.md`](crux-memory-custody/SKILL.md) — a ClawHub
  [Agent Skill](https://docs.openclaw.ai/clawhub/skill-format): YAML frontmatter
  + instructions that tell an OpenClaw agent to write/recall durable memory
  through the `crux` MCP server, and to run the import/scan on demand.
- [`openclaw.mcp.snippet.json`](openclaw.mcp.snippet.json) — the `mcpServers`
  block to merge into `~/.openclaw/openclaw.json`, wiring the `crux` MCP server
  to your **local** daemon.

## Install

1. Run a local Crux daemon (MCP on `127.0.0.1:14801`) and export
   `CRUX_AGENT_TOKEN`.
2. Merge `openclaw.mcp.snippet.json` into `~/.openclaw/openclaw.json` and restart
   the OpenClaw gateway.
3. Copy `crux-memory-custody/` into your OpenClaw skills directory (e.g.
   `~/.openclaw/skills/crux-memory-custody/`), or publish it to ClawHub
   (published skills are MIT-0).
4. Seed the store from your existing memory:
   `corecruxctl openclaw import ~/.openclaw/workspace` then
   `corecruxctl openclaw scan`.

## Supply-chain rule (binding)

The shipped MCP config uses OpenClaw's **HTTP transport** to a local daemon — it
pulls **no npm/npx packages** and downloads nothing at runtime, so there is no
dependency to pin.

If your OpenClaw build lacks HTTP-transport MCP support and needs a stdio bridge
(e.g. `mcp-remote`), **do not** use `npx -y` / `@latest`. Install the bridge once
at an exact, reviewed version and reference the installed binary:

```bash
npm install -g mcp-remote@<pinned-reviewed-version>   # never -y / @latest
```

```jsonc
{ "mcpServers": { "crux": {
  "command": "mcp-remote",
  "args": ["http://127.0.0.1:14801/mcp", "--header", "Authorization: Bearer ${CRUX_AGENT_TOKEN}"]
} } }
```

## Skeleton limitations (operator to-do)

- Transport is assumed to be OpenClaw's `type: "http"` MCP support; confirm on
  your build (tracked upstream at openclaw/openclaw#43509) — otherwise use the
  pinned stdio bridge above.
- Not yet published to ClawHub (publishing needs an account + passport-signed
  release); this is a local skeleton for review.
- The skill instructs the agent to *dual-write* durable memories to Crux; it does
  not intercept OpenClaw's own markdown writes. Full write-through interception
  is a follow-up.
