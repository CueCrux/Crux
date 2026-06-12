#!/bin/sh
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
# .deb postinstall: reload unit files; never enable or start the service —
# starting the daemon is the operator's explicit action.
set -e
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi
echo "crux-daemon installed. Start it when YOU are ready:"
echo "  sudo systemctl enable --now crux     # service (data in /var/lib/crux)"
echo "  crux                                  # or foreground, current user"
echo "Console: http://127.0.0.1:14800   Docs: docs/getting-started.md"
exit 0
