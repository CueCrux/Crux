---
name: host-deploy-runbook
description: Deploy runbook for the demo host — repoint the tag, data volume is preserved, smoke probe after
metadata: 
  node_type: memory
  type: project
  modified: 2026-09-01T11:00:00.000Z
---

1. Repoint the release tag.
2. Restart the unit.
3. Probe `/readyz`, then one substantive endpoint.

Dangling on purpose: [[a-memory-that-does-not-exist]].
