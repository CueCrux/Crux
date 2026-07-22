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
