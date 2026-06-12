# Code Health Harvest

Crux's **code intelligence** is built by *ingesting what compilers, linters, and
grep already know* — never by writing a bespoke analyzer. The
`corecruxctl code-health harvest` subcommand runs a tool battery over a repo,
normalizes the findings, and (with `--push`) writes them to the daemon fact
store, where the console **Workbench → Code health** tab surfaces them.

> Founding constraint: **ingest, don't analyze.** Every finding names the tool
> that produced it and the `commit_sha` it was measured at. If a finding class
> needs a new analyzer, it is out of scope.

## The battery (v1)

| Lane | Tool | Finding class | Notes |
|------|------|---------------|-------|
| dead/unused code | `cargo check --message-format=json` | `dead` | `dead_code` + `unused_*` warnings |
| unused deps | `cargo machete` | `unused-dep` | keyed to the manifest path |
| stubs + markers | grep (built-in scan) | `stub`, `todo` | `todo!()`/`unimplemented!()`/`unreachable!()` → stub; `TODO`/`FIXME`/`dbg!()` → todo |
| unused TS exports | `ts-prune` (or `knip`) | `dead` | only when a `package.json` is present |

Tools absent from `PATH` are recorded in `tools_missing` so a thin report is
never mistaken for "clean". The grep lane always runs (pure filesystem).

## Usage

```bash
# Print normalized JSON (the codehealth.v1 envelope)
corecruxctl code-health harvest --repo /path/to/repo

# Human-readable summary
corecruxctl code-health harvest --repo /path/to/repo --format text

# Push findings to the daemon fact store (M2)
corecruxctl code-health harvest --repo /path/to/repo --push \
  --http http://127.0.0.1:14800 \
  --token-file ~/.config/cuecrux/crux-tokens/anthropic.jwt
```

`--push` token resolution order: `--token-file`, then `$CRUX_AGENT_TOKEN`, then
`~/.config/cuecrux/crux-tokens/anthropic.jwt`. The token needs `facts:write`
scope on the target daemon.

## Fact model

Findings live under `entity="codehealth:<repo>"` (the repo's leaf dir name):

- **Finding facts** — key `<class>:<file>:<line>` (unused-dep appends the crate
  name); value is a compact JSON `{class, file, line, message, tool, commit_sha}`;
  `horizon_class="volatile"` (counts move daily).
- **Run summary** — one `run:<date>` fact per harvest day; value carries
  `{commit_sha, counts, resolved, total, tools_ran, tools_missing}`;
  `horizon_class="medium"`.

### Reconciliation (desired-state)

`--push` reconciles the store to exactly the current finding set:

- **Unchanged** finding (same key + value) → skipped (no write, no version bloat).
- **Changed** finding (same key, new value) → old fact deleted, new written.
- **Resolved** finding (in store, absent from harvest) → deleted, so
  `query_facts` never returns a fixed finding as current.
- **Same-day re-run** → the `run:<date>` summary is refreshed; `run:<other-day>`
  summaries are left untouched as audit history.

The daemon's automatic `(entity, key)` version chain does **not** hide
superseded versions from queries, which is why machine-generated volatile
findings are reconciled by delete-then-write rather than relying on
append-supersession.

## Nightly harvest (operator-provisioned)

The harvest is **not** auto-installed. To run it nightly per watched repo, add a
cron entry (or systemd timer) on the daemon host:

```cron
# 02:30 nightly — harvest each watched repo into codehealth:<repo>
30 2 * * *  cd /srv && for r in Crux PlanCrux AuditCrux; do \
  corecruxctl code-health harvest --repo "/srv/$r" --push \
    --http http://127.0.0.1:14800 \
    --token-file /root/.config/cuecrux/crux-tokens/anthropic.jwt \
    >> /var/log/code-health-harvest.log 2>&1; done
```

Rollback = remove the cron entry. The harvester is pull-only (stdout) unless
`--push` is given, and inert unless run.

## Console

**Workbench → Code health** tab (`/console#/`, the `cx-workbench` page) renders
the findings: a searchable list with per-class counts, each row expanding to
message · tool · commit. It reads `/v1/console/facts?q=codehealth` and degrades
to a baked demo set when the daemon is unreachable (e.g. the static
`agent-observability.html` preview).

## Querying findings as an agent

```text
query_facts(entity="codehealth:Crux", token_budget=500)   # current findings + run summary
query_facts(query="codehealth dead", token_budget=500)    # dead-code findings across repos
```

Always pass `token_budget` (default 500). Findings are excluded from
boot-banner recall except the scoped `— CODE HEALTH —` section (M6).

## Context files — per-file intent injected on Read (M5)

The MemoryHook pattern applied to code: a `code:<repo>:<path>` fact (key
`context`) carries a file's intent/constraints, and a **PreToolUse(Read)** hook
injects it (≤500 tokens) as `additionalContext` when an agent is about to Read
that file — so the agent doesn't re-derive the file's purpose from source.

**Default-OFF.** Enable per the `hooks.code_context` convention by setting
`CRUX_HOOK_CODE_CONTEXT=1` and wiring the `crux-hook code-context` PreToolUse
hook in `settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Read",
        "hooks": [{ "type": "command", "command": "crux-hook code-context" }] }
    ]
  }
}
```

The hook is fail-open: disabled, no fact, or an unreachable daemon → a plain
`allow` with no injection; it never blocks the Read and never errors out of the
tool call. It carries a freshness guard — if the file's mtime is newer than the
fact's `stored_at`, the injected block is tagged `⚠ context may be stale`.

### Seeding context facts

Write a `code:<repo>:<path>` fact with key `context` (stable horizon):

```bash
curl -X PUT -H "Authorization: Bearer $JWT" -H 'content-type: application/json' \
  -d '{"entity":"code:Crux:crates/corecruxd/src/work.rs","key":"context",
       "value":"Owns gate resolution. INVARIANT: never write a gate without a passport.",
       "horizon_class":"stable"}' \
  http://127.0.0.1:14800/v1/facts
```

Or via the `store_fact` MCP tool. Operators/agents author these; a skeleton
harvest from module doc-comments (`//!` headers) is a noted follow-up, not yet
shipped.
