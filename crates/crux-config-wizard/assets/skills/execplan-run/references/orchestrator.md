# Orchestrator lane

The session working directly with the operator. It **picks, guards, dispatches, shepherds and
closes**. It does not implement milestones itself when a worker can — but it is the only
session allowed to mutate the plan file and the board.

## 0. Boot (once)

Trust the `crux-boot-banner` `system-reminder` if present — it already carries mode, fact
count, `update_status`, live sessions and the top of the board. Only if it is absent or shows
`Boot banner degraded`:

```
sync_status()          # local_only / degraded → no cross-agent handoffs this session
update_status()        # behind → get_bootstrap("docs","upgrade") before deploys
                       # ahead / diverged → STOP, escalate
ep board 10
```

Capture your session id once, cheaply:
`cuecrux_session(intent="session_review", max_capabilities=5, hide_exclusions=true)` →
`export EP_SESSION=<session_id>`. Without it `ep announce` cannot claim.

## 1. Pick

```
ep board 10
```

Take the **first** entry. The list is already in recommended order. Exceptions:

- Operator named a plan → use that.
- Row is `blocked` with a `blocker_reason` → that is a **question to surface**, not work to
  start. Report it and take the next row.
- `!! dependency_cycles` in the output → two plans declare `Depends on` each other. Ordering
  is undefined. Surface it. If exactly one plan in the cycle has `orchestrat` in its slug,
  that plan's `Depends on` line is the inverted edge — orchestrators are parents
  (PLANS.md). Flip it to `Extended by`, don't guess further.

## 2. Preflight

```
ep preflight <slug>
```

Read the block and stop on any of these:

| Signal | Action |
|---|---|
| `⚠ NOT on origin/main` | The plan is an uncommitted draft — invisible to every other session and to the daemon. Commit it before executing. |
| `⚠ tree DIFFERS from origin/main` | You are reading another branch's version of the plan. Re-read via `git show origin/main:<path>`. |
| `Status:` says shipped/superseded but board says `in_progress` | Board drift. Fix the plan's `Status:` line, don't re-do the work. |
| `blocked_by=` non-empty | Those plans must close first. Go back to step 1. |
| a peer announces the same slug or overlapping paths | Coordinate before editing — comment on the work item or `create_handoff`. Advisory, never a hard stop, but silence here is how two sessions ship the same milestone twice. |
| OD refs listed | Check they are still `open` in `docs/master-plan/tracking/open-decisions.md`. Score them **now** (see closeout.md → OD sweep) rather than mid-milestone. |

Then pull just enough prior context — budgeted:

```
query_facts(query="execplan:<slug>", token_budget=2000)     # prior gates + decisions
get_session(session_id="execplan:<slug>")                   # where the last session stopped
```

The `gate:M<n-1>` fact tells you what the previous session actually finished. Trust it over
the Progress checkboxes; checkboxes rot, facts carry `commit_sha`.

## 3. Claim

```
ep announce <slug> M<n> "<comma,separated,paths>"
ep worktree <repo-path> <slug>
```

`ep announce` prints `⚠ overlap` lines. Surface every one to the operator before proceeding.

Then persist the intent so a crash mid-plan is resumable:

```
save_session(session_id="execplan:<slug>",
             state={current_milestone, worktree, branch, gates_passed, next_action})
```

Re-announce on **every** milestone switch — a stale intent pinned to M1 while you work M4 is
worse than none, because peers trust it.

## 4. Dispatch or implement

Implement inline when the milestone is small or you already hold the context.

Delegate to a worker (subagent or another session) when the milestone is self-contained and
you want to keep orchestrator context clean. The worker gets the worktree path, the slug, the
milestone id and its `Gate:` clause — nothing else. It follows
[milestone-loop.md](milestone-loop.md) and returns the gate result.

**One write-agent per claimed path-set.** Read-only research agents may run in parallel;
mutating agents may not share a tree. For a genuine cross-session pass, use `create_handoff`
rather than a second write-agent.

## 5. Shepherd

PR handling is **automatic when the plan has not changed** — no menu, no confirmation:

```
ep pr open <worktree-dir> "<slug> M<n>: <title>"
ep pr watch <worktree-dir>
ep pr merge <worktree-dir>
```

Escalate to the operator instead of merging when any of these hold:

- The milestone's `Gate:` clause is not actually satisfied.
- The plan's risk class is `high` and this is the prod-cutover milestone — that needs a
  passport-attributed human gate (`/v1/work/{id}/transitions`).
- Checks are red for a reason that is not a known infra flake. A flaky test on a
  correctness path (crypto, auth, recovery) is a **defect report**, not a re-run: loop it
  10–20× and `uniq -c` before touching the retry button.
- A sibling PR touches the same struct. Two non-stacked PRs each adding a required field to
  one struct both go green and still break `main`.

`gh pr merge --auto` disarms when mergeability reports UNKNOWN. `ep pr merge` prints the
`auto=` flag afterwards — if it is `false`, re-arm rather than assuming it stuck.

## 6. Advance or close

More milestones → back to step 3 with `M<n+1>` (re-announce, same worktree).

Last milestone gated → [closeout.md](closeout.md). Do not skip it; skipped closeout is
precisely why the board grows.

## Chat budget

Three lines per milestone (`Did / Gate / Next`). One block at pick time naming the plan and
why. Everything else goes to the plan file or a fact.
