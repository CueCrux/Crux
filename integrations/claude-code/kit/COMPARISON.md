# Kit vs. do-it-yourself (the honest version)

**The compaction-survival capability is free.** It is source-available in the
Crux repo at `integrations/claude-code/compaction-survival/`, and MIT-licensed
in the standalone [`proof-of-loss-hook`](https://cuecrux.com) mini-repo. You can
wire it up yourself in about ten minutes with two shell scripts and a
`settings.json` edit. Nothing here is behind a licence key.

So what does the $9 kit actually buy you? Convenience and time — not the trick.

| | DIY (free) | $9 Kit |
|---|---|---|
| The two hooks (snapshot + restore) | ✅ copy from the repo | ✅ bundled |
| Wiring into `~/.claude/settings.json` | hand-edit JSON, get the paths right | ✅ one command, idempotent, validates the JSON |
| **Codex** config too | figure out Codex's hook format yourself | ✅ tested `~/.codex/hooks.json`, installed for you |
| Proof harness | ✅ `proof.sh` is in the repo | ✅ bundled |
| Human-readable proof **report** | build your own | ✅ `proof-report.sh` renders the capture/restore log to markdown |
| Self-contained delivery (no repo checkout) | clone the repo | ✅ single zip, installs offline |
| Updates for 7 days if a hook contract changes | watch the repo yourself | ✅ included |

### When to just DIY

If you're comfortable editing `settings.json`, only use Claude Code (not Codex),
and don't need a shareable report — **clone the repo, it's free, you lose
nothing.** We'd rather you use the capability than not.

### When the kit pays for itself

You want it working across **both** Claude Code and Codex in one command, you
want a report you can paste into a standup or a client update, and $9 is cheaper
than the twenty minutes of reading hook docs and debugging JSON paths.

### What we will never do

- Paywall the capability. It's free forever (that's a vow, not a launch promo).
- Call this "open-source" — the Crux repo is source-available under the CueCrux
  Community Licence (CCL); only the `proof-of-loss-hook` mini-repo is MIT.
- Pretend the kit is magic. It's packaging around free scripts, sold honestly.
