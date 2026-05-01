# Troubleshooting

Common issues and how to fix them.

## Daemon won't start

### "FATAL: CORECRUXD_AUTH_MODE is required"

```
FATAL: CORECRUXD_AUTH_MODE is required. Set it explicitly to one of: off, dev_scopes, jwt_hs256, jwt_jwks.
```

**Cause:** `CORECRUXD_AUTH_MODE` has no default. You must set it explicitly.

**Fix:**
```bash
# For local development:
export CORECRUXD_AUTH_MODE=off

# Or copy the example config:
source config.example.env
```

### "address already in use"

**Cause:** Another process is using port 14800.

**Fix:**
```bash
# Find the process:
lsof -i :14800

# Kill it, or use a different port:
CORECRUXD_HTTP_PORT=14900 ./corecruxd
```

### "No such file or directory" for data directory

**Cause:** The directory in `CORECRUXD_DATA_DIR` doesn't exist.

**Fix:**
```bash
mkdir -p ./data
CORECRUXD_DATA_DIR=./data ./corecruxd
```

## Queries return empty results

### No .ccxi indexes

**Cause:** BM25 retrieval requires `.ccxi` companion indexes. These are built at seal time when `CORECRUXD_BUILD_CCXI=1`.

**Fix:**
```bash
export CORECRUXD_BUILD_CCXI=1
# Restart the daemon. New segments will get indexes at seal time.
```

### Data hasn't been sealed yet

Appended events live in an active (unsealed) head segment. BM25 queries only search sealed segments.

**Fix:** Wait for the segment to seal (automatic), or use the fact store for small-scale storage:
```bash
curl -s -X PUT http://localhost:14800/v1/facts \
  -H "Content-Type: application/json" \
  -d '{"entity": "test", "key": "greeting", "value": "hello world"}'
```

## MCP connection issues

### Can't connect to MCP server

**Cause:** The built-in MCP server runs on port **14801**, not 14800. The HTTP
API is on 14800, and MCP can be disabled with `CORECRUXD_MCP_ENABLED=false`.

**Fix:** Check your MCP client config points to `http://localhost:14801/mcp`.

### "unknown tool" error

**Cause:** Tool name is misspelled or not in the catalogue.

**Fix:** Call `tools/list` to see all 22 available tools:
```bash
curl -s -X POST http://localhost:14801/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}'
```

### Agent identity shows "anonymous"

**Cause:** The server is allowing anonymous MCP access because
`CRUX_AGENT_TOKEN` / `CRUX_AGENT_TOKENS` is not configured, or your client is
not sending a bearer token in anonymous mode.

**Fix:**
```bash
# Generate a token:
openssl rand -hex 32

# Configure it on the server and in the MCP client:
export CRUX_AGENT_TOKEN="your-generated-token"
```

If you configure agent tokens on the server, unauthenticated `POST /mcp`
requests return `401 Unauthorized` instead of silently downgrading to
anonymous access.

### Handoff verification fails after restart or on another replica

**Cause:** `CRUX_MCP_HANDOFF_SECRET` is unset, so handoff package verification
keys are process-local and rotate on restart.

**Fix:**
```bash
export CRUX_MCP_HANDOFF_SECRET="$(openssl rand -hex 32)"
```

Use the same secret on every replica that needs to accept MCP handoff packages.

## Health check failures

### `/readyz` returns 503

**Cause:** The daemon is still initialising or has encountered a critical error.

**Fix:**
```bash
# Check the full health response:
curl -s http://localhost:14800/healthz | jq .

# Check logs for errors:
# (if using Docker)
docker compose logs corecrux
```

### `/healthz` works but `/readyz` doesn't

`/healthz` confirms the process is alive. `/readyz` confirms it can serve traffic. If only `/healthz` works, the daemon is still loading data or running pre-flight checks.

**Fix:** Wait a few seconds and retry. If it persists, check logs.

## Docker issues

### Container exits immediately

**Cause:** Usually a missing required env var (`CORECRUXD_AUTH_MODE`).

**Fix:**
```bash
# Check logs:
docker compose logs corecrux

# The docker-compose.yml should set CORECRUXD_AUTH_MODE.
# If not, add it:
#   environment:
#     - CORECRUXD_AUTH_MODE=dev_scopes
```

### Build takes too long

First Rust build downloads and compiles all dependencies (~5 minutes).

**Fix:** Use the pre-built image if available:
```yaml
image: ghcr.io/cuecrux/crux-daemon:latest
```

## Store integrity errors

### SEGMENT_CORRUPT

```
Run: corecruxctl verify-store --data-dir ./data --scope recent
```

This checks BLAKE3 hashes and CROWN receipt chains. If corruption is confirmed, the affected segment is quarantined.

### EPOCH_MISMATCH

**Cause:** A segment was written by a different node epoch.

**Fix:** Usually safe to ignore if you're running a single node. If persists:
```bash
corecruxctl verify-store --data-dir ./data --scope full
```

## Quick diagnostic commands

| What | Command |
|---|---|
| Is the daemon alive? | `curl http://localhost:14800/healthz` |
| Is it ready for traffic? | `curl http://localhost:14800/readyz` |
| How many metrics? | `curl http://localhost:14800/metrics \| wc -l` |
| Verify data integrity | `corecruxctl verify-store --data-dir ./data` |
| Check MCP tools | `curl -X POST http://localhost:14801/mcp -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'` |
