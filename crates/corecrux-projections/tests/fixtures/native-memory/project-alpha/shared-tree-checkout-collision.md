---
name: shared-tree-checkout-collision
description: Sibling sessions reset the SAME nested repo tree and uncommitted edits vanish; use a worktree per lane
metadata: 
  node_type: memory
  type: project
  originSessionId: 00000000-0000-4000-8000-000000000002
  modified: 2026-08-19T09:12:00.000Z
---

Two sessions sharing one checkout will fight over the index.

Use `git worktree add` per lane. Related: [[toolchain-outside-path]], [[never-written-down]].
