#!/usr/bin/env bash
# Crux Substrate concept — static server (ES modules need HTTP, not file://)
cd "$(dirname "$0")/.."   # serve UI-prototype/ so ../assets logo resolves
exec python3 -m http.server 8321
