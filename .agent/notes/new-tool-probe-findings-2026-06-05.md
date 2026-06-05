# Crux Daemon — new-function probe findings (2026-06-05)

Session passport `ce:4e6c4e2a:local` (group=claude-work), daemon `local_only`, 2,256 local facts.
Flags live: `AGENT_PASSPORTS=1`, `EPHEMERAL_GC=1`, `ORCHESTRATORS=1`, `PUNCHCARD=advisory`.

Exercised the freshness/memory suite, the orchestrator + punchcard coordination plane, and the
work/project surface. All mutations done on a clearly-named throwaway entity
(`test-fixture-cruxprobe-2026-06-05`) + a `/tmp` punchcard resource, then swept.

## What works cleanly (no action)

- `memory_freshness`, `memory_sweep_candidates` (empty — 0 stale, matches banner), `memory_set_horizon`
  (volatile/medium/stable/none), `memory_reverify` (mints a `Reverify` receipt + re-anchors clock).
- `memory_pin`, `memory_history` (walks the version chain correctly).
- `store_fact` + `supersedes`: correctly sets `superseded_by` on the retired fact and hides it from
  default `query_facts`; `include_superseded:true` re-exposes it. ✔
- `query_facts` time-decay ranking + `effective_confidence`; `memory_view` paginated shape.
- `check_punchcard` honors advisory mode (`held_by_other:true, enforce:false`).
- `punch_in` / `punch_out` full lifecycle with acquire/release receipt chain.
- `memory_acknowledge_use` returned an envelope (note: schema says gated `CORECRUXD_FEATURE_MEMORY_ACK=1`
  default-off, but it succeeded — flag is on here or gating isn't enforced).
- `cuecrux_session` capability plan (14 caps, plan hash, receipt).

## HIGH — correctness

1. **`memory_edit` does not retire the prior version in the recall plane.**
   `memory_history` shows v2 note records `supersedes: f_89e2ca…` (version chain correct), BUT default
   `query_facts` returned BOTH v1 and v2, each with `superseded_by: null`. After an in-place edit, recall
   surfaces the **stale value alongside the corrected one**. The version-chain `supersedes` and the
   cross-entity `superseded_by` (which `query_facts` filters on) are not unified — `store_fact+supersedes`
   sets the latter, `memory_edit` does not. This makes `memory_edit` actively misleading for recall.

2. **`memory_edit` silently drops the pin.** Edited a `pinned:true` fact → new version `pinned:false`
   (`memory_view` confirms). Pins protect against decay (#3) and scoped-forget (#9); losing the pin on
   edit is a data-protection footgun.

3. **Pinned fact was soft-deleted by scoped-forget.** Spec: "Pinned facts survive scoped-forget (#9)."
   `memory_forget_dry_run` = 4, `memory_forget` = 4 soft-deleted, post-forget `query_facts` = 0 rows.
   The pinned v1 note id was among the 4. (Compounded by #2, but the literal pinned fact was swept.)

## MEDIUM — passport / auth wiring (likely M5-cutover gaps)

4. **Passport not bound on orchestrator/punchcard writes.** `create_orchestrator` → top-level
   `actor:"anonymous"`; `punch_in` → stored `holder_passport:"anonymous"` even though I passed
   `ce:4e6c4e2a:local`. The facts plane correctly records `actor:"claude-work"`. The new coordination
   tools aren't wired to the passport resolver — anonymous leases/orchestrators defeat the "who's working
   on this" purpose and break owner-scoped `force_release` attribution.

5. **`update_work_state` → `loopback 401`.** `create_work` on the same project succeeds, but the state
   transition fails auth; passport-value-independent (tried `ce:…` and `anonymous`). MCP loopback-auth
   gap on a write route the earlier work-panel 401 fix didn't cover.

6. **`attach_to_orchestrator` rejects a passport `member_ref` with a bare `400`.** Work-item refs (`w_…`)
   attach fine; passport ref `ce:4e6c4e2a:local` → opaque 400, though the schema says `member_ref` accepts
   "a passport id or a work item id." Either passport refs are unsupported (fix the doc) or the principal-id
   form is wrong (return a useful validation error).

## LOW — polish / ergonomics

7. **No orchestrator close/delete/archive tool.** Surface is create + attach + detach + list only;
   `create_orchestrator` has a `state` enum but there's no `update_orchestrator`. Orphaned orchestrators
   can't be cleaned via MCP. (Left residue — see below.)
8. **`store_fact` has no `horizon_class`/`freshness_horizon` param** — must follow with `memory_set_horizon`
   (two calls). MCP schema only exposes `supersedes`.
9. **Age-unit inconsistency:** `query_facts`/`memory_freshness` rows use `age_hours`; the same response's
   `envelope.memories_used` uses `age_days`.
10. **`memory_forget_dry_run` structured field not surfaced.** Prose says "see structured
    `facts_that_would_be_affected`" but the MCP result returns only the prose string, not the array.
11. **`create_work` schema example uses `project_id:"default"`,** which doesn't exist (only `plancrux`);
    a missing project returns an opaque `loopback 404` instead of "project not found."
12. **`memory_edit` sets `actor:null`** on the new fact (store_fact records `claude-work`) — weakens the
    Art.12/13 attribution trail.

## Residue left for operator (couldn't self-clean — tools missing/broken)

- Orchestrator `orc_298710feaeb640dfb76ed1d98549360a` ("probe-squad-2026-06-05", active, 0 members) — no delete/archive tool.
- Work item `w_ed89ed7af7fa46e680c23bfd493dc86b` (plancrux, state=planned) — `update_work_state` 401-blocked.

All fixture facts + the punchcard were cleaned.
