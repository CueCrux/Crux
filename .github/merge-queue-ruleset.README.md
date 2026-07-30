<!-- Copyright (c) 2026 CueCrux Ltd. -->
<!-- Licensed under the Apache License, Version 2.0. -->

# `main` merge-queue ruleset

`merge-queue-ruleset.json` is the versioned source of truth for the GitHub
**merge queue and runner-policy merge guard** on `main`. It is **not applied
automatically** — it is committed here for review and reproducibility. Applying
or updating it is a separate, deliberate human-gated step.

Full rationale, rollback, and milestone gates: ExecPlan
`crux-ci-merge-queue-wiring-2026-06-26` (in `PlanCrux/.agent/execplans/`).

## What it does

Tests the *speculative combined state* of stacked PRs ahead of time and merges
them as a train, so PRs no longer have to re-test against `main` every time
another PR lands. It replaces the `strict` ("require branches up to date")
retest tax with an equivalent, parallelised guarantee.

It also has no configured bypass actors, requires one code-owner approval from
someone other than the last pusher, and requires the trusted
`Workflow runner policy` check. The check runs from the default-branch
implementation and treats the candidate tree only as data.

## Runner-policy bootstrap order

Do not add the required status context before the workflow has landed: the
first PR cannot run a `pull_request_target` workflow that does not yet exist on
its base branch.

1. Restrict the persistent runner group to the three selected workflows pinned
   to `refs/heads/main` (see `docs/self-hosted-runner.md`).
2. Merge the initial runner-policy workflow/checker with existing protections
   and explicit code-owner review.
3. Confirm the push-to-main `Workflow runner policy` run succeeds.
4. Apply/update this ruleset and confirm `bypass_actors` remains empty.
5. Open a test PR and verify the check is required; then try deleting or
   neutralising the policy workflow and confirm the trusted check fails.

Any other protected long-lived base branch must carry the same trusted
workflow and an equivalent required-check/ruleset. Otherwise do not accept PRs
to that branch. The selected-workflow runner-group restriction remains the
runtime boundary even when a merge guard is absent.

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

All PR and merge-queue required checks now run on disposable GitHub-hosted
workers. A single **code-change** queue build fans out to about 10 non-trivial
jobs:

- `ci.yml` — Lint, Test, MSRV, Coverage (4)
- `docs.yml` — Build rustdoc (1; the Pages-deploy job is push+main-only and is skipped)
- `audit.yml` — Cargo deny policy, Cargo audit, Licence check (3)
- `semver.yml` — Semver Compatibility (1)

With `max_entries_to_build: 2`, the queue requests at most about 20 hosted jobs
concurrently, on top of in-flight PR/push CI. Keep the cap at 2 until duration,
hosted concurrency, and cost data justify raising it.

## Required checks the queue waits on

Every one of these must fire on the `merge_group` event or the queue hangs
(wired in PR #280): **Lint, Test, MSRV (1.88.0), Coverage** (`ci.yml`),
**Build rustdoc** (`docs.yml`), **Cargo deny policy, Cargo audit, Licence
check** (`audit.yml`), **Semver Compatibility** (`semver.yml`), and
**Workflow runner policy** (`runner-policy.yml`).

The legacy `ci:fallback` label is additive and is not a security or
merge-queue fallback. Do not disable the ruleset merely to bypass a red
security-policy check.
