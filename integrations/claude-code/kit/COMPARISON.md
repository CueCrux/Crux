# Kit vs. do-it-yourself (the honest version)

**The compaction-survival capability is free.** It is source-available in the
Crux repo at `integrations/claude-code/compaction-survival/` under the CueCrux
Community Licence (CCL), and separately MIT-licensed in the standalone
`proof-of-loss-hook` mini-repo. You can wire it up yourself in about ten minutes
with two shell scripts and a `settings.json` edit. Nothing here is behind a
licence key.

So what does the $9 kit actually buy you? Convenience and time — not the trick.

| | DIY (free) | $9 Kit |
|---|---|---|
| The two hooks (snapshot + restore) | ✅ copy from the repo | ✅ bundled |
| Wiring into `~/.claude/settings.json` | hand-edit JSON, get the paths right | ✅ one command, idempotent, validates the JSON, refuses to clobber symlinked configs |
| **Codex** config too | wire the same hooks into `~/.codex/hooks.json` yourself | ✅ done for you in the same command |
| Self-test | ✅ `selftest.sh` is in the repo | ✅ bundled |
| Human-readable event report | build your own | ✅ `event-report.sh` renders the local capture/restore log to markdown (metadata by default) |
| Self-contained delivery (no repo checkout) | clone the repo | ✅ single zip, installs offline |
| Updates for 7 days if a hook contract changes | watch the repo yourself | ✅ included |

### When to just DIY

If you're comfortable editing `settings.json` and don't need the Codex wiring or
the report done for you — **clone the repo, it's free, you lose nothing.** We'd
rather you use the capability than not.

### When the kit pays for itself

You want it working across **both** Claude Code and Codex in one command, you
want a local event report without writing one, and $9 is cheaper than the twenty
minutes of reading hook docs and debugging JSON paths.

### Honesty notes

- We never paywall the capability. It's free forever (a vow, not a launch promo).
- The Crux repo is **source-available under the CueCrux Community Licence (CCL)**;
  the standalone `proof-of-loss-hook` mini-repo is **MIT-licensed**.
- The event report reads an unsigned local log — it's a convenience report, not a
  signed or verifiable record. Snapshot bodies can contain sensitive transcript
  excerpts, so the report keeps them private (mode 0600 on disk) unless you pass
  `--include-sensitive-snapshot`.
- The kit is packaging around free scripts, sold honestly.
