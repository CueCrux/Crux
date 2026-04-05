#!/bin/bash
# CoreCrux Quick Start
# Starts the daemon, stores a fact, queries it, then cleans up.

set -euo pipefail

CORECRUXD_DATA_DIR=/tmp/crux-demo
CORECRUXD_HTTP_PORT=14800

echo "==> Starting corecruxd..."
CORECRUXD_DATA_DIR="$CORECRUXD_DATA_DIR" ./target/release/corecruxd &
DAEMON_PID=$!
sleep 2

cleanup() {
  echo "==> Shutting down..."
  kill "$DAEMON_PID" 2>/dev/null || true
  rm -rf "$CORECRUXD_DATA_DIR"
}
trap cleanup EXIT

BASE="http://localhost:${CORECRUXD_HTTP_PORT}"

echo "==> Health check"
curl -s "$BASE/healthz" | jq .
echo

echo "==> Store a fact"
curl -s -X PUT "$BASE/v1/facts" \
  -H 'Content-Type: application/json' \
  -d '{
    "entity": "project",
    "key": "status",
    "value": "Phase 1 complete",
    "confidence": 0.95
  }' | jq .
echo

echo "==> Query facts"
curl -s "$BASE/v1/facts?query=project" | jq .
echo

echo "==> Append events"
curl -s -X POST "$BASE/v1/append" \
  -H 'Content-Type: application/json' \
  -d '{
    "stream_id": "docs",
    "events": [
      {
        "event_type": "doc.created",
        "content_type": "text/plain",
        "payload": "CoreCrux provides append-only event storage with BM25 retrieval."
      }
    ]
  }' | jq .
echo

echo "==> Done!"
