---
name: execplan-run
description: "Execute and CLOSE an ExecPlan end-to-end in CueCrux — the execution half that execplan-synthesize/appraise/research (authoring half) hand off to. Runs the milestone loop: claim from the ranked board, announce focus for collision detection, worktree, implement, gate fact, PR, shepherd checks, merge, next milestone, close out, reap the worktree. Invoke when the user says: 'run this execplan', 'execute the plan', 'pick up the next milestone', 'resume <slug>', 'what should I work on', 'close this plan out', 'ship M3', 'shepherd the PR', 'reap stale worktrees', 'clean up finished plans', or when a session opens as an ORCHESTRATOR dispatching plan work. Use when plans are accumulating faster than they close."
---

# ExecPlan Run

The four `execplan-*` skills author plans. **None of them close one.** That is why 63 plans
sit `in_progress` and 25 of those have zero milestones gated (measured 2026-08-06). This
skill is the execution and closeout loop.

Announce at start: "Using execplan-run — <lane>." Then work the phases.

## Two lanes

| Lane | Who | Reads |
|---|---|---|
| **Orchestrator** — pick, check collisions, dispatch, shepherd, close | the session working with the operator | [references/orchestrator.md](references/orchestrator.md) |
| **Worker** — one milestone, gate to gate | a worktree session or subagent | [references/milestone-loop.md](references/milestone-loop.md) |

Default to **orchestrator** unless handed a specific `<slug> M<n>` to implement.
Closeout is the orchestrator's job and it is not optional:
[references/closeout.md](references/closeout.md).

## Mechanics live in a script, not in your context

`scripts/ep` does every board read, coordination call, worktree op, and PR poll and prints a
compact block. Use it instead of hand-rolling `curl | jq` or `gh` loops — that is the whole
token argument.

```
ep board [n]                        # ranked open work, already in recommended order (~650 tok)
ep preflight <slug>                 # grounding + board row + live peers + worktrees, one block
ep announce <slug> [M<n>] [paths]   # declare focus; prints overlaps. ttl 0 clears
ep worktree <repo> <slug> [branch]  # worktree off origin/main, named for the slug
ep pr open|watch|merge <dir> [...]  # push, poll checks, squash-merge
ep reap [--dry] [repo]              # delete worktrees whose branch already merged
```

Facts stay on MCP (`store_fact` / `query_facts`) — the script never writes them, because
facts must be deliberate.

## The loop

```
0 BOOT      once per session — banner, or ep board
1 PICK      ep board → take the FIRST entry (it is already ranked)
2 PREFLIGHT ep preflight <slug> → grounding, blockers, peers, ODs
3 CLAIM     ep announce + ep worktree + save_session
4 MILESTONE implement → test → commit → store_fact gate:M<n>   ← repeats
5 PR        ep pr open → watch → merge   (automatic; no menu unless the plan changed)
6 CLOSE     last milestone → Status flip, OD sweep, ep reap, announce ttl=0
```

Steps 4–5 repeat per milestone. Steps 2 and 6 are where ODs get scored (below).

## Rules that are not negotiable

**Grounding before executing.** Read `Status:` from `origin/main`, never the working tree —
a main checkout is usually on some other session's branch. `ep preflight` does this. A plan
authored on a stale branch inverts (greenfield vs already-shipped).

**Take the first board entry.** `ranked=1` already sorted unblocked-before-blocked,
`in_progress`-before-`planned`, foundations-before-dependents. Re-ranking by hand wastes the
sort. A `blocked` row with a `blocker_reason` is a question for the operator, not a task.

**Resume, never fork.** If the request matches an `in_progress` plan's next milestone, resume
it. Starting a parallel plan for work already in flight is the failure mode that produced
1127 plan files against 244 open items.

**One gate fact per milestone, always.** A milestone with no `gate:M<n>` fact did not happen
as far as the board is concerned — that is exactly how 25 plans reached `in_progress` at 0/N.

**Never stack PRs.** Base is always `main`. Auto-retarget races the merge in these repos.

**Worktrees are reaped at close**, not left for later. 20 stale worktrees were sitting in the
workspace when this skill was written.

**ODs batch to the edges.** Score and register open decisions at preflight (step 2) or
closeout (step 6). Mid-milestone OD work is only justified when the milestone genuinely
cannot proceed without the decision — and then it becomes a `blocked` transition with a
`blocker_reason`, surfaced to the operator, not a silent stall.

## Grounded tool surface — verified 2026-08-06

Claude Code sessions here do **not** get `coord_status`, `coord_announce`, `list_work`,
`punch_in`, or `execplan_gate` on the MCP surface, despite CLAUDE.md §11 naming them. They
exist in the daemon but are not advertised to this client. `ep` reaches them over HTTP:

| Need | Reality |
|---|---|
| ranked board | `GET /v1/work?ranked=1&limit=N&fields=slim` |
| live peers | `GET /v1/coord/active` — the route is `active`, not `status` |
| declare focus | `POST /v1/coord/announce` |
| gate a milestone | MCP `store_fact` (`execplan_gate` is not surfaced) |
| orchestrator objects | **501, gated default-OFF.** `create_orchestrator` / `attach_to_orchestrator` are scaffolds. Do not build on them. |

`cuecrux_session()` with no `max_capabilities` returns ~4k tokens of capability graph. Pass
`max_capabilities: 5, hide_exclusions: true` when all you need is the `session_id`.

## Delegation — do not restate these

| Need | Skill |
|---|---|
| brief → Draft plan | `execplan-synthesize` |
| score milestones, risk class, `deps:M<n>` | `execplan-appraise` |
| prior rationale + coverage gaps | `execplan-research` |
| a lesson that keeps recurring | `execplan-distill` |
| the Crux MCP phase runbook (budgets, fact schemas) | `crux-phase` |
| "what's open?" read-only digest | `execplan-overseer` agent |

This skill sequences them; it does not duplicate them.

## Token discipline

`token_budget` on every retrieval call — 500 confirmation, 2000 scan, 4000 design pull.
Chat carries state transitions only: what changed, gate result, next milestone. Tables,
audits and summaries go to files and are referenced by path.

Per-milestone chat is three lines:

```
Did:  <one clause>
Gate: PASS|FAIL — <probe>
Next: M<n+1> | <escalation>
```
