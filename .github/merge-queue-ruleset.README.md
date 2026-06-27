<!-- Copyright (c) 2026 CueCrux Ltd. All rights reserved. -->
<!-- Licensed under the CueCrux Community Licence (CCL v1.0). -->

# `main` merge-queue ruleset

`merge-queue-ruleset.json` is the versioned source of truth for the GitHub
**merge queue** on `main`. It is **not applied automatically** — it is committed
here for review and reproducibility. Enabling the queue (a gated cutover) is a
separate, deliberate step.

Full rationale, rollback, and milestone gates: ExecPlan
`crux-ci-merge-queue-wiring-2026-06-26` (in `PlanCrux/.agent/execplans/`).

## What it does

Tests the *speculative combined state* of stacked PRs ahead of time and merges
them as a train, so PRs no longer have to re-test against `main` every time
another PR lands. It replaces the `strict` ("require branches up to date")
retest tax with an equivalent, parallelised guarantee.

## Apply / inspect / disable (do not run without the M3 human gate)

```bash
# Apply (creates the ruleset) — M3 cutover, gated:
gh api -X POST repos/CueCrux/Crux/rulesets \
  --input .github/merge-queue-ruleset.json

# List ruleset ids:
gh api repos/CueCrux/Crux/rulesets --jq '.[] | {id, name, enforcement}'

# Operational pause (runners down — see "Runner load" below):
gh api -X PUT repos/CueCrux/Crux/rulesets/<id> \
  --input <(jq '.enforcement="disabled"' .github/merge-queue-ruleset.json)

# Full rollback:
gh api -X DELETE repos/CueCrux/Crux/rulesets/<id>
```

## Parameter choices

| Parameter | Value | Why |
|---|---|---|
| `merge_method` | `MERGE` | Preserve merge history — `main`'s commit shape is unchanged from today (OD-MQ-1, operator decision 2026-06-26). |
| `max_entries_to_build` | `2` | **The runner-safety knob.** Caps how many speculative combinations build at once — see "Runner load". |
| `max_entries_to_merge` | `3` | Batch up to 3 PRs into one CI run; fewer total runs. |
| `min_entries_to_merge` | `1` | A lone PR is never blocked waiting for a batch to fill. |
| `min_entries_to_merge_wait_minutes` | `5` | Brief window to let a batch coalesce before merging a single entry. |
| `grouping_strategy` | `ALLGREEN` | A batch only merges if the whole group passes; GitHub bisects on failure. |
| `check_response_timeout_minutes` | `60` | A required check that never reports fails the entry after 60 min instead of wedging the queue forever (backstop). |

## Runner load (why `max_entries_to_build: 2`)

All required-check jobs run on the finite self-hosted `[self-hosted, ci]` pool.
A single **code-change** queue build fans out to ~9 non-trivial self-hosted jobs:

- `ci.yml` — Lint, Test, MSRV, Coverage (4)
- `docs.yml` — Build rustdoc (1; the Pages-deploy job is push+main-only and is skipped)
- `audit.yml` — Cargo deny policy, Cargo audit, Licence check (3)
- `semver.yml` — Semver Compatibility (1)

With `max_entries_to_build: 2`, the queue demands **at most ~18 self-hosted
jobs concurrently** — on top of any in-flight PR/push CI. This pool has a
history of saturation/disk incidents, so the cap stays at 2 until headroom data
(M3/M4) justifies raising it. Bump deliberately, one step at a time, watching
concurrent-run counts.

## Required checks the queue waits on

Every one of these must fire on the `merge_group` event or the queue hangs
(wired in PR #280): **Lint, Test, MSRV (1.88.0), Coverage** (`ci.yml`),
**Build rustdoc** (`docs.yml`), **Cargo deny policy, Cargo audit, Licence
check** (`audit.yml`), **Semver Compatibility** (`semver.yml`).

> **Caveat (OD-MQ-2):** the `ci:fallback` label escape hatch does **not** work
> inside the queue — queue entries are not PRs and cannot be labelled. If the
> self-hosted pool is down, *disable the ruleset* (above) so PRs merge directly
> and the fallback path works, then re-enable when runners recover.
