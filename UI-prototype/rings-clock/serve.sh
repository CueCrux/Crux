#!/usr/bin/env bash
# Rings clock-of-work concept — static server (plain HTML, no build step)
cd "$(dirname "$0")"
exec python3 -m http.server 8323
