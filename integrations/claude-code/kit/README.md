# Compaction Survival Kit ($9)

Stop your AI coding agent forgetting your plan every time it compacts.

When Claude Code or Codex compacts a long conversation, it summarizes the
transcript and drops your open todos, the files you were editing, and the
guard-rails you set ("don't touch `billing.ts`"). This kit installs two hooks
that snapshot that working state **before** compaction and hand it back
**after** — so the agent keeps the plot.

## What's in the box

- **`install.sh`** — one command. Installs the hooks and wires **both** Claude
  Code and Codex, idempotently, validating the JSON it writes.
- **Tested configs** — `claude-settings.snippet.json` and
  `codex-hooks.snippet.json`, known-good.
- **`hooks/proof.sh`** — assert-based proof the capability works on your machine.
- **`proof-report.sh`** — renders your capture/restore log into a readable
  markdown report.
- **`COMPARISON.md`** — an honest kit-vs-free breakdown.
- 7 days of support.

## Install

```bash
unzip compaction-survival-kit.zip && cd compaction-survival-kit
bash install.sh
```

Then restart Claude Code / Codex. That's it.

```bash
bash hooks/proof.sh      # prove it works
bash proof-report.sh     # readable report of what it captured
```

## The capability is free

**To be completely clear: the compaction-survival capability is free and
source-available** in the Crux repo at
`integrations/claude-code/compaction-survival/`, and MIT-licensed in the
standalone `proof-of-loss-hook` mini-repo. You can wire it up yourself for
nothing. This kit sells the *packaging* — the one-command dual-agent installer,
the tested Codex config, the proof report, and support — not the trick. See
[`COMPARISON.md`](COMPARISON.md) for exactly what you're paying for.

("Free" / "source-available" — the Crux repo is under the CueCrux Community
Licence, not open-source; the mini-repo is MIT.)

## Requires

`jq` on your PATH. Nothing else.
