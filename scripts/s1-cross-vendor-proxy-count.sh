#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# Read-only S1 proxy count over provider-tagged observations and fact actors.
#
# Usage:
#   bash scripts/s1-cross-vendor-proxy-count.sh --window-days 14 --json
#   bash scripts/s1-cross-vendor-proxy-count.sh --since 2026-06-23T00:00:00Z --human
#   bash scripts/s1-cross-vendor-proxy-count.sh --data-dir /var/lib/corecruxd --window-days 14
#   bash scripts/s1-cross-vendor-proxy-count.sh --self-test
#
# Environment:
#   CRUX_HTTP_URL             Daemon HTTP base. Default: http://127.0.0.1:14800
#   CRUX_AGENT_TOKEN          Bearer token for authenticated daemons.
#   CORECRUXD_ADMIN_TOKEN     Fallback bearer token for older operator envs.
#   CRUX_S1_PROVIDERS         Comma-separated provider probe list.
#
# Exit codes:
#   0 — count or self-test succeeded
#   1 — daemon request, parsing, or self-test failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/s1_cross_vendor_proxy_count.py" "$@"
