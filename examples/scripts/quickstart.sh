#!/bin/bash
# CoreCrux Quick Start
# Builds (if needed), starts the daemon, runs through the core APIs, then cleans up.
#
# Usage: ./examples/scripts/quickstart.sh

set -euo pipefail

CORECRUXD_DATA_DIR=/tmp/crux-demo
CORECRUXD_HTTP_PORT=14800
CORECRUXD_AUTH_MODE=off   # Local demo only — use jwt_hs256 or jwt_jwks in production.
CORECRUXD_QUERY_TEXT_SEARCH=1
BASE="http://localhost:${CORECRUXD_HTTP_PORT}"
MCP_URL="http://localhost:14801/mcp"

# ── Pre-flight checks ─────────────────────────────────────────────

for cmd in curl jq; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: '$cmd' is required but not found. Install it and try again."
    exit 1
  fi
done

if lsof -i ":${CORECRUXD_HTTP_PORT}" &>/dev/null 2>&1; then
  echo "ERROR: Port ${CORECRUXD_HTTP_PORT} is already in use."
  echo "  Kill the process or set CORECRUXD_HTTP_PORT to a different port."
  exit 1
fi

BINARY="./target/release/corecruxd"
if [ ! -f "$BINARY" ]; then
  echo "==> Binary not found at $BINARY. Building (this takes a few minutes)..."
  cargo build --release --bin corecruxd
fi

# ── Start daemon ───────────────────────────────────────────────────

echo "==> Starting corecruxd..."
CORECRUXD_DATA_DIR="$CORECRUXD_DATA_DIR" \
  CORECRUXD_AUTH_MODE="$CORECRUXD_AUTH_MODE" \
  CORECRUXD_QUERY_TEXT_SEARCH="$CORECRUXD_QUERY_TEXT_SEARCH" \
  "$BINARY" &
DAEMON_PID=$!

cleanup() {
  echo "==> Shutting down..."
  kill "$DAEMON_PID" 2>/dev/null || true
  rm -rf "$CORECRUXD_DATA_DIR"
}
trap cleanup EXIT

# ── Wait for readiness ─────────────────────────────────────────────

echo "==> Waiting for daemon to be ready..."
for i in $(seq 1 30); do
  if curl -sf "$BASE/readyz" &>/dev/null; then
    echo "    Ready after ${i}s."
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "ERROR: Daemon did not become ready within 30 seconds."
    exit 1
  fi
  sleep 1
done

# ── Health check ───────────────────────────────────────────────────

echo ""
echo "==> Health check"
curl -s "$BASE/healthz" | jq .

# ── Store a fact ───────────────────────────────────────────────────

echo ""
echo "==> Store a fact"
curl -s -X PUT "$BASE/v1/facts" \
  -H 'Content-Type: application/json' \
  -d '{
    "entity": "project",
    "key": "status",
    "value": "Phase 1 complete",
    "confidence": 0.95
  }' | jq .

# ── Query facts ────────────────────────────────────────────────────

echo ""
echo "==> Query facts"
curl -s "$BASE/v1/facts?query=project" | jq .

# ── Update the fact (version 2) ───────────────────────────────────

echo ""
echo "==> Update the fact (creates version 2)"
curl -s -X PUT "$BASE/v1/facts" \
  -H 'Content-Type: application/json' \
  -d '{
    "entity": "project",
    "key": "status",
    "value": "Phase 2 in progress — 3 milestones remaining",
    "confidence": 0.90
  }' | jq .

# ── View fact history ──────────────────────────────────────────────

echo ""
echo "==> Fact history (shows both versions)"
curl -s "$BASE/v1/facts/entity/project/key/status/history" | jq .

# ── Feature flags ──────────────────────────────────────────────────

echo ""
echo "==> Runtime feature flags"
curl -s "$BASE/v1/version" | jq .

# ── MCP discovery ──────────────────────────────────────────────────

echo ""
echo "==> MCP tool catalogue"
curl -s -X POST "$MCP_URL" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq '.result.tools | length'

# ── Append events (best-effort: dataplane may be disabled) ─────────

echo ""
echo "==> Append events (if dataplane enabled)"
APPEND_STATUS=$(curl -s -o /tmp/crux-append.json -w '%{http_code}' -X POST "$BASE/v1/append" \
  -H 'Content-Type: application/json' \
  -d '{
    "tenant_id": "demo",
    "stream_type": "docs",
    "stream_id": "docs",
    "events": [
      {
        "event_id": "evt-quickstart-1",
        "occurred_at": "2026-04-09T12:00:00Z",
        "event_type": "doc.created",
        "content_type": "text/plain",
        "payload": "CoreCrux provides append-only event storage with BM25 retrieval."
      }
    ]
  }')
if [ "$APPEND_STATUS" = "201" ]; then
  jq . /tmp/crux-append.json
else
  echo "    Append skipped or unavailable (HTTP $APPEND_STATUS)"
  jq . /tmp/crux-append.json
fi
rm -f /tmp/crux-append.json

# ── Done ───────────────────────────────────────────────────────────

echo ""
echo "==> Done! CoreCrux is running at $BASE"
echo "    Try: curl $BASE/healthz"
echo "    Stop: kill $DAEMON_PID"
