```
 ██████╗██████╗ ██╗   ██╗██╗  ██╗
██╔════╝██╔══██╗██║   ██║╚██╗██╔╝
██║     ██████╔╝██║   ██║ ╚███╔╝
██║     ██╔══██╗██║   ██║ ██╔██╗
╚██████╗██║  ██║╚██████╔╝██╔╝ ██╗
 ╚═════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
```

# CoreCrux Community Edition

[![CI](https://github.com/CueCrux/Crux/actions/workflows/ci.yml/badge.svg)](https://github.com/CueCrux/Crux/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-82%25-green)](https://github.com/CueCrux/Crux)
[![Licence](https://img.shields.io/badge/licence-CCL--1.0-blue)](LICENCE.md)
[![MSRV](https://img.shields.io/badge/MSRV-1.88.0-orange)](rust-toolchain.toml)
[![Docker](https://img.shields.io/badge/docker-ghcr.io%2Fcuecrux%2Fcrux-blue)](https://ghcr.io/cuecrux/corecrux-community)

A source-available, single-binary retrieval engine with built-in cryptographic receipts.

CoreCrux is an append-only event store with fused BM25 + graph signal retrieval and CROWN receipts baked into every operation. Every query result is signed, every retrieval path is auditable, and every gap in coverage is reported.

## Features

| Feature | Description |
|---|---|
| **Append-only event store** | Sealed segments with BLAKE3 integrity and crash recovery |
| **CPU BM25 retrieval** | Full-text search via `.ccxi` companion indexes with PForDelta compression |
| **Graph signal fusion** | Relation-aware retrieval that boosts connected documents |
| **CROWN receipts** | Ed25519-signed receipts on every operation with BLAKE3 chain |
| **Tenant isolation** | Per-tenant hash partitioning across shards |
| **CLI tooling** | `verify-store`, `replay`, receipt inspection, and more |
| **Prometheus metrics** | Built-in `/metrics` endpoint for observability |
| **HTTP + gRPC + MCP** | Human API, data-plane API, and built-in agent tooling |

## Quickstart

### Docker (recommended)

```bash
docker compose up -d
```

The bundled compose stack is for local development and publishes `14800`
(HTTP) and `14801` (built-in MCP) on host loopback only.

### Binary

```bash
# Linux (x86_64)
curl -sSL https://github.com/CueCrux/Crux/releases/latest/download/corecruxd-linux-amd64 -o corecruxd
chmod +x corecruxd
CORECRUXD_AUTH_MODE=dev_scopes CORECRUXD_DATA_DIR=./data ./corecruxd
```

### Build from Source

```bash
git clone https://github.com/CueCrux/Crux.git
cd Crux
cargo build --release
CORECRUXD_AUTH_MODE=dev_scopes CORECRUXD_DATA_DIR=./data ./target/release/corecruxd
```

## Five-Minute Walkthrough

1. **Start the server:**
   ```bash
   docker compose up -d
   # or: source config.example.env && ./target/release/corecruxd
   ```

2. **Verify it's ready:**
   ```bash
   curl -sf http://localhost:14800/readyz && echo "ready"
   ```
   Wait for `{"ok": true}` before sending requests. `/healthz` checks if the process is alive; `/readyz` checks if it can serve traffic.

3. **Inspect enabled features:**
   ```bash
   curl -s http://localhost:14800/v1/version | jq .
   ```
   Response:
   ```json
   {
     "version": "0.1.0",
     "commit": "abc1234",
     "features": {
       "text_search": false,
       "graph_expand": false,
       "self_observe": false,
       "mcp": true
     },
     "sync": {
       "mode": "local_only",
       "configured": false,
       "background_sync_enabled": false
     }
   }
   ```
   `text_search` and append/data-plane features are deployment-dependent. The
   fact store, sessions, health endpoints, and built-in MCP server work in the
   default Community Edition runtime. `sync.mode` tells you whether the node is
   running local-only, manual sync, full background sync, or a degraded remote
   sync configuration.

4. **Store a fact:**
   ```bash
   curl -s -X PUT http://localhost:14800/v1/facts \
     -H "Content-Type: application/json" \
     -d '{
       "entity": "project",
       "key": "status",
       "value": "Phase 1 complete — 12 milestones delivered",
       "confidence": 0.95
     }'
   ```
   Response:
   ```json
   {
     "fact_id": "f_01J...",
     "entity": "project",
     "key": "status",
     "value": "Phase 1 complete — 12 milestones delivered",
     "confidence": 0.95
   }
   ```

5. **Query facts:**
   ```bash
   curl -s "http://localhost:14800/v1/facts?query=project+status&token_budget=500"
   ```
   Response:
   ```json
   {
     "facts": [
       {
         "fact_id": "f_01J...",
         "entity": "project",
         "key": "status",
         "value": "Phase 1 complete — 12 milestones delivered",
         "confidence": 0.95
       }
     ],
     "total_tokens": 28
   }
   ```

6. **Inspect the built-in MCP server:**
   ```bash
   curl -s -X POST http://localhost:14801/mcp \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}' | jq '.result.tools | length'
   ```
   Expected output:
   ```text
   22
   ```

7. **Verify store integrity:**
   ```bash
   corecruxctl verify-store --data-dir ./data --scope recent
   ```

If you are integrating CoreCrux into another system, agents can pull the
seeded onboarding playbooks at runtime with
`get_bootstrap(topic="docs", query="integration")`. For upgrades and rollback
planning, pair `update_status()` or `/v1/version.update` with
`get_bootstrap(topic="docs", query="upgrade")` and
`get_bootstrap(topic="docs", query="backup")`. Those playbooks live in
[`crates/crux-observe/bootstrap_data/docs.json`](crates/crux-observe/bootstrap_data/docs.json)
and can be updated in-repo without adding a hosted onboarding dependency.

## API Reference

### Core Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/healthz` | Health check with build metadata |
| GET | `/readyz` | Readiness check |
| GET | `/metrics` | Prometheus metrics |
| POST | `/v1/admin/append` | Append events to a stream (`/v1/append` compatibility alias) |
| POST | `/v1/query/text-search` | BM25 + graph signal retrieval |
| POST | `/v1/query/graph-expand` | Graph traversal with budget |
| POST | `/v1/query/time-range` | Temporal range queries |
| PUT | `/v1/facts` | Store a shared fact |
| GET | `/v1/facts` | Query shared facts |
| GET | `/v1/receipts/{id}` | Retrieve a CROWN receipt |
| GET | `/v1/receipts/{id}/verification` | Verify receipt signature |

### CLI Tools

| Command | Description |
|---|---|
| `corecruxctl verify-store` | Cryptographic integrity check on corpus |
| `corecruxctl replay` | Deterministic replay with drift classification |
| `corecruxctl receipts` | Receipt tooling and export |
| `corecruxctl ccxi` | Companion index inspection |
| `corecruxctl projections` | Projection state management |

## Architecture

```mermaid
graph TD
    cruxmcp[crux-mcp<br/>MCP Server<br/>22 tools]
    observe[crux-observe<br/>Self-Observation]
    sync[crux-sync<br/>Outbox Sync]
    contrib[crux-contrib<br/>Contributions]
    corecruxd[corecruxd<br/>HTTP + gRPC Daemon]
    corecruxctl[corecruxctl<br/>CLI Tool]
    retrieval[corecrux-retrieval<br/>BM25 + Graph Fusion]
    memory[corecrux-memory<br/>Fact + Session Store]
    projections[corecrux-projections<br/>Entity State]
    receipts[corecrux-receipts<br/>CROWN Receipts]
    storage[corecrux-storage<br/>Shard Store]
    index[corecrux-index<br/>.ccxi Indexes]
    segment[corecrux-segment<br/>Sealed Segments]
    frame[corecrux-frame<br/>Frame Encoding]
    types[corecrux-types<br/>Core Types]
    proto[corecrux-proto<br/>gRPC Proto]

    cruxmcp --> memory
    cruxmcp --> retrieval
    cruxmcp --> observe
    observe --> memory
    corecruxd --> cruxmcp
    corecruxd --> observe
    corecruxd --> memory
    corecruxd --> retrieval
    corecruxd --> projections
    corecruxd --> receipts
    corecruxd --> storage
    corecruxd --> proto
    corecruxctl --> storage
    corecruxctl --> receipts
    retrieval --> index
    retrieval --> projections
    projections --> storage
    projections --> segment
    storage --> segment
    storage --> frame
    index --> segment
    index --> frame
    segment --> frame
    receipts --> types
    frame --> types
```

## Configuration

CoreCrux is configured via environment variables:

| Variable | Default | Description |
|---|---|---|
| `CORECRUXD_DATA_DIR` | `../CoreCruxData/v3` | Data directory for segments |
| `CORECRUXD_HTTP_PORT` | `14800` | HTTP API port |
| `CORECRUXD_GRPC_PORT` | `4007` | gRPC API port |
| `CORECRUXD_MCP_PORT` | `14801` | Built-in MCP port |
| `CORECRUXD_MCP_ENABLED` | `true` | Enable built-in MCP server |
| `CORECRUXD_BUILD_CCXI` | `0` | Build `.ccxi` indexes at seal time |
| `CORECRUX_LOG_FORMAT` | `text` | Log format (`text` or `json`) |
| `CORECRUXD_UPDATE_CHECK_ENABLED` | `true` | Background git-based update checks |
| `CORECRUXD_UPDATE_CHECK_REMOTE` | `origin` | Tracked git remote for update checks |
| `CORECRUXD_UPDATE_CHECK_REF` | `main` | Tracked branch for update checks |

See `config.example.env` for the full list with descriptions.

## MCP Server (for AI Agents)

CoreCrux includes a built-in MCP server on port **14801** with 22 tools for retrieval, fact storage, sessions, sync, update status, decisions, and multi-agent handoff.

### Connect an agent

**Claude Desktop / Claude Code:** Copy `examples/mcp-configs/claude-desktop.json` into your Claude config. See `examples/mcp-configs/README.md` for paths.

**Cursor:** Copy `examples/mcp-configs/cursor.json` to `.cursor/mcp.json`.

**Verify the connection:**
```bash
curl -s -X POST http://localhost:14801/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}' | jq '.result.tools | length'
# Expected: 22
```

If you configure `CRUX_AGENT_TOKEN` or `CRUX_AGENT_TOKENS`, send the matching
Bearer token on MCP requests. If you rely on handoff packages across restarts or
multiple replicas, also set `CRUX_MCP_HANDOFF_SECRET`.

### Agent quickstart (first 3 calls)

1. `get_bootstrap("patterns")` — learn usage patterns
2. `store_fact(entity="test", key="hello", value="world")` — store your first fact
3. `query_facts(query="hello")` — retrieve it

For maintenance and onboarding:

- `update_status()` or `/v1/version.update` tells humans and agents whether the checkout is `current`, `behind`, `ahead`, `diverged`, `disabled`, or `unavailable`.
- Use `get_bootstrap(topic="docs", query="upgrade")` for the upgrade playbook.
- Use `get_bootstrap(topic="docs", query="backup")` for current backup and rollback options.

See `docs/agent-guide.md` for the full agent integration guide.

## Troubleshooting

See `docs/troubleshooting.md` for common issues and fixes.

## Licence

CoreCrux Community Edition is licensed under the [CueCrux Community Licence (CCL v1.0)](LICENCE.md).

- Free to use, read, audit, modify, and build on for internal use
- Contributions welcome via the published process
- Three years after each release, the code converts to Apache 2.0
- GPU acceleration and hosted platform features are not included

Copyright (c) 2026 CueCrux Ltd. All rights reserved.
