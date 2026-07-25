#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# Upload the developer guide into your VaultCrux Documents.
#
# Operator-run: needs YOUR VaultCrux API key + tenant id (never stored here).
#   VAULTCRUX_API_KEY=... VAULTCRUX_TENANT=... [VAULTCRUX_URL=https://vaultcrux.com/api/v1] \
#     bash docs/developer-guide/upload-to-vaultcrux.sh
#
# Posts each chapter to POST /ingest as one document in the `developer-guide`
# corpus (created on first use when auto-create is enabled), shareability
# owner_only. Idempotent per docId: re-running replaces the same documents.

set -euo pipefail
: "${VAULTCRUX_API_KEY:?set VAULTCRUX_API_KEY (your platform API key)}"
: "${VAULTCRUX_TENANT:?set VAULTCRUX_TENANT (your tenant id)}"
BASE="${VAULTCRUX_URL:-https://vaultcrux.com/api/v1}"
CORPUS="${VAULTCRUX_CORPUS:-developer-guide}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for f in "$DIR"/[0-9][0-9]-*.md; do
  slug="$(basename "$f" .md)"
  title="Crux Daemon developer guide — $(sed -n '1s/^# //p' "$f")"
  [ -n "$title" ] || title="Crux Daemon developer guide — $slug"
  printf 'uploading %s ... ' "$slug"
  jq -Rs --arg t "$VAULTCRUX_TENANT" --arg c "$CORPUS" --arg d "crux-devguide-$slug" \
        --arg ti "$title" --arg u "https://github.com/CueCrux/Crux/blob/main/docs/developer-guide/$slug.md" \
        '{tenantId:$t, corpusId:$c, docId:$d, title:$ti, url:$u, content:., shareability:"owner_only"}' "$f" \
    | curl -fsS -X POST "$BASE/ingest" \
        -H "x-api-key: $VAULTCRUX_API_KEY" \
        -H "x-tenant-id: $VAULTCRUX_TENANT" \
        -H 'Content-Type: application/json' \
        --data-binary @- >/dev/null && echo ok
done
echo "done — see $BASE/../documents (Documents section) for the ${CORPUS} corpus."
