# Activity Log — dual-surface "what just happened"

> Status: **M0–M4 shipped.** ExecPlan
> `crux-dual-surface-activity-log-2026-06-18`. Capture + agent lane + human
> page + verify cross-walk, all behind `CORECRUXD_FEATURE_ACTIVITY_LOG`.

The activity log gives every session a rolling, chronological record of what
agents do — captured **once per turn-event** and read two ways off one source
of truth:

- **Agent lane** — a cheap, token-budgeted pull (`GET /v1/activity` + MCP
  `activity_recent`) answering "what just happened in this session" in ~500
  tokens.
- **Human lane** *(M3, pending)* — a console Activity tab rendering the same
  rows with verbatim text + a ✓verify badge.

Both lanes join on `turn_id` and reference the same append id, so the human
view is the agent view with prose rehydrated — they can never disagree.

## Enabling it

Off by default. Set the flag in the daemon's environment:

```
CORECRUXD_FEATURE_ACTIVITY_LOG=1
```

With the flag unset the routes return `404` and the daemon behaves exactly as
before. Optional retention override (default 24h):

```
CORECRUXD_FEATURE_ACTIVITY_LOG_TTL_SECS=86400
```

## The seven categories (`kind`)

`question` · `answer` · `reasoning` · `command` · `fact` · `execplan` ·
`handoff` · `error`

(`reasoning` is best-effort — see OD-15 on harness reasoning capture.)

## Capture — `POST /v1/activity`

Append a journal entry. Requires a write scope (`facts:write` or
`admin:write`) for the body's `tenant_id`. The actor is bound to the
authenticated passport (the body cannot spoof it).

```jsonc
POST /v1/activity
{
  "tenant_id": "acme",
  "session_id": "sess-abc",
  "turn_id": "turn-12",          // optional; the join key to receipts + the human lane
  "kind": "command",
  "text": "ran cargo test -p corecruxd",
  "refs": { "fact_ids": [], "receipt_ids": [], "event_ids": [] },  // optional cross-refs
  "meta": { "tool": "Bash", "intent": "test", "confidence": null }, // optional
  "private": false                // PII: never syncs remote, author-scoped reads
}
```

Response `201` is the persisted `crux.activity.journal_entry.v1` entry, with a
content-addressed `entry_id` that is also recorded in `refs.receipt_ids` (the
append's audit reference). Each append broadcasts an `activity.appended` event
on `/v1/events/stream` (ids + kind only — never the verbatim text).

**Privacy:** reserved-prefix tokens (`__agent::`, `__ops::`,
`__bootstrap__::`) are stripped from `text` on persist and on every read.
`private:true` entries are returned only to the authoring passport and never
sync to a remote.

## Agent lane — `GET /v1/activity`

```
GET /v1/activity?tenant_id=acme&session=sess-abc&token_budget=500
                 [&since=<seq>] [&kinds=command,error]
```

- `token_budget` is **mandatory** (QC.2) — a missing/zero value is a `400`.
- Returns compact rows newest-first, privacy-scoped, trimmed to fit the
  budget (using the same estimator as `tool_trace_recent`).

```jsonc
{
  "session_id": "sess-abc",
  "token_budget": 500,
  "returned": 3,
  "truncated": false,
  "rows": [
    { "turn_id": "turn-12", "seq": 41, "ts": "...", "kind": "command",
      "tool": "Bash", "intent": "test", "confidence": null,
      "fact_refs": [], "receipt_ids": ["act_…"], "preview": "ran cargo test …" }
  ]
}
```

`preview` is truncated — never the verbatim text. To get the full text for a
turn, deref it:

```
GET /v1/activity/turn/{turn_id}?tenant_id=acme&session=sess-abc
```

returns the full `entries[]` with verbatim `text` and `refs`.

### MCP — `activity_recent`

Same pull from chat; applies a default `token_budget` of 500.

```jsonc
activity_recent({ "session_id": "sess-abc", "kinds": ["error","command"], "token_budget": 500 })
```

## Human lane — `/console/activity`

A new page on the embedded console (linked from the console header). It is a
self-contained, dependency-free page that:

- streams live rows via `EventSource('/v1/events/stream?types=activity.appended')`,
- backfills via `GET /v1/activity` (tenant / session / token_budget inputs),
- colour-codes rows by kind, filters client-side by free text,
- expands a row to its verbatim `text` via `GET /v1/activity/turn/{turn_id}`
  with a ✓verify badge per receipt ref.

Deep-link with `?session=<id>&tenant_id=<t>`. The page is inert (its API calls
return 404) unless `CORECRUXD_FEATURE_ACTIVITY_LOG=1`. Iterate without a
rebuild by pointing `CORECRUXD_CONSOLE_DEV_PATH` at a dir containing
`activity.html`.

## Verification cross-walk (M4)

The agent-lane row's `receipt_ids` for a turn are byte-identical to the
human-lane deref's `refs.receipt_ids` for the same `turn_id` — guaranteed by
the parity test `activity_turn_id_parity_agent_vs_human_lane`. The console
✓verify badge (M3) reuses the existing `receipt_verify` path against those
ids.

## What's not here yet

- **Reasoning capture (category 3)** — best-effort, pending OD-15.
- **Full CROWN signing of each append** — today the append id + the
  `activity.appended` projection row satisfy the audit-trail requirement
  (T.4); CROWN co-signing is a tracked follow-up.
- **Hook clients** — `POST /v1/activity` is the ingestion contract;
  per-workstation Claude Code hooks (prompt/stop/posttooluse → append) are an
  opt-in step, not shipped enabled.
