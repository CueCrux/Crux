---
name: toolchain-outside-path
description: The linux toolchain EXISTS at ~/.local/toolchain/bin but is not on PATH; prefix PATH and the build runs directly
metadata: 
  node_type: memory
  type: project
  originSessionId: 00000000-0000-4000-8000-000000000001
  modified: 2026-08-11T13:46:55.903Z
---

The toolchain is installed but the harness ships a PATH that does not include it.

- Prefix `PATH=~/.local/toolchain/bin:$PATH` and the build runs directly.
- The indirect route through the wrapper is BROKEN — it resolves the host toolchain instead.

See also [[shared-tree-checkout-collision]] and [[host-deploy-runbook]].
