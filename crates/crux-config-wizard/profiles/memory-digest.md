+++
name = "memory-digest"
version = 1
description = "Always-loaded curated-memory index: one line per engram, resolved to a body on demand."
targets = ["claude_md", "agents_md"]
order = 11
risk_class = "medium"
+++

## Crux Memory Digest

The daemon's curated memory tier has not been rendered into this workspace yet,
so this section is a pointer rather than an index.

Generate it with:

```bash
corecruxctl memory distill --native-root '~/.claude/projects/*/memory'   # review the proposals
corecruxctl memory digest  --native-root '~/.claude/projects/*/memory' --accept N
crux-config-wizard regenerate
```

`memory digest` seeds the catalog from the harness-native memory store, accepts
the distillation proposals you name, and writes `.crux/memory-digest.md`. The
wizard composes that file into this section on the next `regenerate`, in both
`CLAUDE.md` and `AGENTS.md` — the same index reaches Claude Code and Codex.

Until then, curated memory is reachable only by calling `engram_resolve`
(manifest mode lists it; `names: ["<slug>@v1"]` returns a body).
