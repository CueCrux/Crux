#!/bin/sh
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
# .deb postremove: reload units. Data in /var/lib/crux is NEVER deleted by
# package removal — export/delete is the operator's explicit action.
set -e
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
  echo "crux-daemon removed. Your data was kept at /var/lib/crux (delete it"
  echo "yourself if you mean to: sudo rm -rf /var/lib/crux)."
fi
exit 0
