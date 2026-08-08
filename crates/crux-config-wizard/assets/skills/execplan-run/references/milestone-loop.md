# Worker lane — one milestone, gate to gate

You were handed a worktree, a slug, a milestone id and its `Gate:` clause. Do that milestone
and nothing else. Scope creep here is what turns a 5-milestone plan into a 12-milestone one.

## Inputs you should already have

```
slug        execplan slug (no `execplan:` prefix)
milestone   M<n>
gate        the plan's `Gate:` clause for M<n> — the pass/fail criterion
worktree    absolute path; you work here, never in the primary checkout
```

If the `Gate:` clause is missing or is a vibe rather than a criterion, stop and say so. A
gateless milestone cannot be attested, and inventing the criterion yourself means the gate
fact asserts something the plan never agreed to.

## 1. Recall before reading code

```
query_facts(query="execplan:<slug> <milestone topic>", token_budget=2000)
```

Two things you are looking for:

- `gate:M<n-1>` — what the previous milestone actually landed, with its `commit_sha`.
- `incident:*` matching your symptom if you are here to fix something. A recorded `fix_sha`
  beats re-deriving the fix.

**A fact naming a file, function or flag is a claim about when it was written, not now.**
Before acting on one, `Read` the file or grep the symbol. Renamed, removed, or
never-merged is the common case in an active area.

## 2. Verify the ground

Cheap checks that prevent expensive wrong work:

```bash
git -C <worktree> log --oneline -3
git -C <worktree> merge-base --is-ancestor origin/main HEAD && echo "based on current main"
```

If a prior session claimed the work exists, confirm it against `origin/main` — not against a
local branch, and not by trusting a subagent's grep. Subagents that grep `origin/main`
without fetching first report false absences; `git fetch` before any absence claim, and
re-verify any load-bearing "X doesn't exist" yourself.

`git grep -- 'crates/*/src'` matches nothing and reads as "no consumer". Run a positive
control before believing a negative result.

## 3. Implement

Smallest change that satisfies the `Gate:` clause. Match surrounding code — comment density,
naming, idiom. A fix goes at the root, in the shared function all callers route through, not
in the one caller the ticket named.

## 4. Test — the real suite, not a subset

Run what the change actually touches:

- Rust daemon behaviour → `cargo test --workspace` or `-p crux-integration-tests`.
  **Not just `-p corecruxd`.** A milestone that passed per-crate tests and two reviews still
  broke an integration test and the bundled-desktop approval flow.
- Rust lint gate is `-D warnings`. Run `cargo fmt` + `cargo clippy` before pushing.
- Engine/TS → pnpm 10.18.2 in CI; overrides live in `pnpm-workspace.yaml`.

**Never pipe the test run through `tail`.** `cargo test | tail -N` returns *tail's* exit code
and truncates the `test result` lines — exit 0 there is not a green gate. Capture to a file
and read the summary.

If a test on a correctness path (crypto, auth, recovery, money) fails intermittently, that is
a defect report about the code. Loop it 10–20× and `uniq -c` the outcomes before you consider
it flaky. If it asserts a property stronger than the design guarantees, assert the guaranteed
property — never re-run until green.

## 5. Commit

One commit per milestone. Message names the slug and milestone, and carries agent attribution
so the audit trail resolves:

```
<slug> M<n>: <what changed>

Gate: <the criterion> — <how it was verified>

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
```

## 6. Gate fact — the step that makes it real

```
store_fact(entity="execplan:<slug>", key="gate:M<n>",
           value={status:"passed"|"failed"|"blocked",
                  date:"<YYYY-MM-DD>", commit_sha:"<sha>",
                  tests_passing:<bool>, artifacts:["<path>","<pr-url>"],
                  notes:"<one line>"})
```

`commit_sha` is required (QC.1). Without this fact the board still shows the milestone
undone — 25 plans reached `in_progress` at 0/N exactly this way.

Failed or blocked is a legitimate outcome. Record it with the reason. A missing fact is
worse than a `failed` one, because it is indistinguishable from a session that crashed.

Benchmarks in the milestone need their own fact, and `corpus` is mandatory:

```
store_fact(entity="bench:<id>", key="result",
           value={metric, value, corpus, lane_flags, commit_sha, run_id})
```

Naming the wrong corpus (LME-S vs LME-M) is the misattribution this rule exists to stop.

## 7. Update the plan, then report

In the plan file: tick the `Progress` box for M<n>, and add a `Decision log` line with
`commit_sha` for any non-trivial choice you made. If you have no checkout, write through the
`execplan_write` MCP tool — it validates against PLANS.md and commits that single file. Never
write into the daemon's projection root; it is a pull-only replica and anything written
straight in becomes an orphan.

Report three lines and stop:

```
Did:  <one clause>
Gate: PASS|FAIL — <probe>
Next: M<n+1> | <blocker>
```

Report at the boundary, not only at the end. Silence is indistinguishable from failure —
if you hit a blocker, name it immediately and say when the next signal is due.

## Do not

- Do not start M<n+1> because it looked small. Return to the orchestrator.
- Do not `git reset --hard` or `git branch -D`. `--abort` only.
- Do not refactor adjacent code the milestone did not name.
- Do not write durable artefacts into a scratchpad directory — they vanish.
