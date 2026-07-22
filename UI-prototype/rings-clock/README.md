# Rings — clock of work (concept prototype)

Signature-visual concept for the Crux console: the ExecPlan portfolio as an
animated clock. New plans enter at 12:01, age clockwise, retire at 11:59 into
the completed ledger. Rings are time; sectors are plans; dots/bars are facts.

- **Data**: a snapshot of 223 real ExecPlan projections (provenance-dated)
  pulled from `GET /v1/work?source=execplans` on 2026-07-21/22, embedded as
  `PLANS_RAW`. The two traced plans (`crux-daemon-buyer-fit-buildout`,
  `cross-site-auth-sso`) carry their real facts; other sectors show
  milestone-derived density until each gets a `query_facts` call.
- **Live-wire swap points**: `/v1/work?source=execplans` (plans + provenance +
  token_burn), `/v1/facts?query=execplan:<slug>` (cells), receipts by seq.
- **Controls**: spin / reset clock · dots / bars · edge outward / inward ·
  start / end window · play (replays May → July) · wheel zoom + drag pan ·
  click a dot or bar for its card.
- **Run**: `./serve.sh` → http://localhost:8323/  (or just open index.html —
  no modules, works from file://)

Lineage: rounds 1–3 of the signature-visual exploration (Loom + Rings) live as
claude.ai artifacts; this folder is the first in-repo landing of the Rings.
Related: `UI-prototype/console-3d/` (clay-substrate concept, 2026-06-11).

## Versions

`index.html` is always the latest. Prior builds are kept verbatim in `versions/`
(besides git history) so older iterations can be opened side-by-side:

- `versions/v4.2-census.html` — census mode, hover-named sectors, binned rim
  token bars, drawn click-cards (pre-pane).
- v4.3 (current `index.html`) — event-aligned gradient rim charts, slide-out
  detail pane, ledger-click plan filter, thicker progress arcs.
- `versions/v4.3-pane-eventcharts.html` — rim-mounted event-aligned token
  charts (pre-move-to-pane).
- v4.4 (current `index.html`) — token chart relocated into the detail pane as
  a horizontal gradient area (cumulative spend, event dots by kind); rim
  carries only the thick progress arcs.
- `versions/v4.4-pane-token-chart.html` — token chart in pane, orange
  in-progress palette, no rim track arcs, no kind/agent filters.
- v4.5 (current `index.html`) — rim track arcs (segment extent, gapped;
  complete = one thick bar), in-progress recoloured purple, state-colours
  toggle (green/purple/red), kind filter (gates / decisions-OD / memory /
  handoffs) and agent-passport filter.
- `versions/v4.5-tracks-filters-state.html` — instant sector exits, 18s
  playback.
- v4.6 (current `index.html`) — play-mode farewell wave: an exiting plan
  fades out-in-out for ~0.5s before collapsing (scrubbing skips it);
  playback slowed 25% (window in ~24s).
- `versions/v4.6-farewell-wave.html` — play-mode farewell wave (retired),
  full-circle solo layout.
- v4.7 (current `index.html`) — farewell wave removed; reset clock also stops
  spin; solo redesigned: plan spans 12→9, the 9→12 quadrant is the event
  ledger (stacked bar per event: tokens + kind + version cap) with the plan's
  own min/mid/max date ticks and min→max range on the 12 o'clock seam;
  sector click now enters solo.
- `versions/v4.7-solo-radial-ledger.html` — solo ledger as radial bars in the
  9→12 quadrant (superseded layout).
- v4.8 (current `index.html`) — solo ledger reworked as a polar gantt: one
  ring per event (earliest outermost, same-day events on adjacent rings by
  exact time), each ring tracks to 9 o'clock then stands up as a vertical
  stacked bar (tokens + kind + version) on the horizontal baseline, with
  per-event date labels and the plan's min→max range on the seam.
- `versions/v4.8-polar-gantt.html` — polar-gantt solo, pre-sessions overlay.
- v4.9 (current `index.html`) — 'sessions' toggle: in solo view, events
  connect into work episodes (same agent, <2.5h gaps — the round-3 rule);
  stitch colour = agent passport, open ring = episode start; untraced plans
  fall back to time-gap inference (grey) and say so.
- `versions/v4.9-sessions-overlay.html` — sessions-overlay experiment
  (episode stitches; retired as unclear).
- v4.10 (current `index.html`) — sessions overlay removed.
- `versions/v4.10-pre-lineage.html` — the return point before lineage/OD.
- v4.11 (current `index.html`) — lineage chords (real depends_on edges, 27
  resolvable in the embedded set; 'lineage' toggle shows all faintly, hover
  always lights a sector's own; dot = the plan being stood on) and amber
  open-decision ticks on sector rims; tooltips and pane list ODs, depends-on
  and extended-by.

## Console integration mock

`console-mock.html` — the rings de-carded onto a console index page:
console-style topbar + pressable lens tiles. Tiles switch the disc between
four lenses: **ExecPlans** (the full clock-of-work incl. solo/ledger/
lineage/filters), **Memory** (sector = fact kind, ring = day, age-fade),
**Sessions** (sector = agent passport), **Receipts** (chain escapement,
illustrative until /v1/receipts/export is wired). Lens views are hover-only
in this mock; the ExecPlans lens keeps full interactivity.
- `versions/console-mock-v1.html` — first console mock (full-width tile row,
  text buttons, no data-graph lens).
- console-mock v2 (current `console-mock.html`) — Data-graph lens (66 live
  facts from the daemon: angle = source date, radius = decay-adjusted
  confidence rank toward the centre, edges = shared entity, click = 2-hop
  neighbourhood); compact icon controls; start/end date pickers; bars on by
  default; tiles compacted to the top-right; completed-plans toggle (off by
  default, auto-on during playback).
- v4.12 / console-mock v3 — adaptive radial time floor: in the active-plans
  view the ring-1 radius snaps to the oldest visible node (corner status
  shows "rings from <date>"), so years of history never crowd live work
  onto the outer rim. Census, solo, and non-work lenses keep the absolute
  window. Priors: versions/v4.11-lineage-od.html, versions/console-mock-v2.html.
