# Closeout — the step that shrinks the board

Runs when the last milestone gates `passed`. Nothing here is optional. Skipping it is the
whole reason 63 plans read `in_progress` and 20 worktrees sit on branches that merged weeks
ago.

Order matters: **verify → OD sweep → plan → facts → reap → release**.

## 1. Verify the plan is actually done

```
query_facts(query="execplan:<slug> gate", token_budget=1500)
```

Every `M0…Mn` declared in `## Milestones` has a `gate:M<n>` fact with `status:"passed"`.
A gap means either the milestone is unfinished or a session forgot the fact — find out which
before closing. Closing over a gap manufactures a false green.

If some milestones are genuinely out of scope now, say so explicitly in the Decision log
with the reason. Silently dropping them is how a plan reads shipped while a third of it never
happened.

## 2. OD sweep — batched here, by design

Open decisions are scored at the **edges** of a plan (preflight or closeout), never scattered
through the milestones. Mid-plan OD work stalls execution for a decision the operator has not
been asked yet.

For each `OD-<n>` the plan references, and each design choice the plan deferred:

**Resolving an OD** takes two artefacts, per PLANS.md closure rule — one is not enough:

1. A `Decision log` line in the owning ExecPlan carrying `commit_sha`.
2. `store_fact(entity="execplan:<slug>", key="decision:<topic>", value={..., commit_sha, actor, risk_class, mitigations})`

Then flip the registry row in the open-decisions registry (`$EP_OD_REGISTRY`, default `docs/master-plan/tracking/open-decisions.md` under the planning repo) to
`resolved` with a resolution paragraph that says what was chosen and **why the alternatives
lost**. Never delete a resolved row.

**Registering a new OD** — when the plan deferred something rather than deciding it: add a
row with question, options considered, owner, `Opened`, and a `decides-by` date. Reference
`OD-<n>` from the plan instead of restating the question.

Lint before you finish: `node tools/status-matrix/check-od-refs.mjs` — every `OD-<n>`
referenced in any `.agent/execplans/*.md` must exist in the registry.

If an OD is still genuinely open at closeout and the plan cannot resolve it, that is fine —
but it must be a **registered row with a decides-by date**, not an unwritten assumption. The
overseer digest surfaces overdue ODs; unregistered ones surface nowhere.

## 3. Close the plan file

Edit the plan file (`$EP_PLANS/<slug>.md`):

- `Status:` line → what actually happened, with commit shas. Prose like "mostly done" keeps
  the plan open and lying; the board parses this line.
- All `Progress` boxes ticked, or explicitly struck with a reason.
- `Decision log` complete, every entry carrying `commit_sha`.
- If a successor plan takes the remainder: `Superseded by [[<slug>]]` as a **line-start
  declaration** — that is what drives the `archive` state. Declare one direction only; the
  projection derives the reciprocal edge.

Commit it. **A plan is real when it is committed** — an uncommitted `.md` is invisible to
every other session and to the daemon. If you have no checkout, use the `execplan_write` MCP
tool (validates, writes, commits that one file, stages nothing else).

## 4. Final facts

```
store_fact(entity="execplan:<slug>", key="milestone:final",
           value={status:"complete", date, commit_sha, milestones_total:<n>,
                  prs:["<url>"], next_action:"none"})
```

Anything learned that will be re-learned by a future session belongs in a fact, not in the
chat log. If the lesson is procedural and keeps recurring, hand it to `execplan-distill` —
an engram arrives *before* the next agent acts, which a fact does not.

Metric-shaped facts (counts, coverage, deploy state) carry a `freshness_horizon` line:
deploy state ~1 day, active-backfill counts 3–7 days, architectural counts 30 days.

## 5. Reap the worktree

```
ep reap --dry <repo>     # look first
ep reap <repo>           # then remove
```

Removes only worktrees under `<repo>-worktrees/` whose branch is already an ancestor of
`origin/main`. It never touches the primary checkout, a tree with uncommitted changes, or a
tree a live process is sitting in.

That last guard earned itself on the first real run: 5 of 24 "stale" worktrees had live
processes inside — running integration-test binaries and an active shell. **Merged-to-main
says the branch is finished; it says nothing about whether someone is standing in the
directory.** Always `--dry` first and read the `in-use` lines.

Do this at closeout, not "later". Later has produced 20 stale worktrees and 43 live ones;
each carries a `target/` directory that can run ~22GB, and a full disk makes **all 43**
`crux-integration-tests --test daemon` cases fail at 0-passed while `/healthz` still returns
200. The worktree leak surfaces as a test outage.

## 6. Release the claim

```
ep announce <slug> "" "" 0        # ttl 0 clears your intent
```

Prefer `create_handoff` over a silent exit when another session inherits anything — it
bundles the facts and work ids so the receiver does not re-query. Handoffs are unavailable
when `sync_status` reports `local_only` or `degraded`; in that case leave the state in
`save_session` and say so.

## 7. Confirm the board moved

```
ep board 10
```

The slug should be gone from the open list. If it is still there, the `Status:` line or the
final fact did not take — fix it now. A closeout that does not move the board did not happen.

## Closing report

Four lines:

```
Closed: <slug> (<n> milestones, <n> PRs)
ODs:    <resolved ids> | opened <new ids> | none
Reaped: <worktree path> | none
Board:  <n> open (was <n>)
```
