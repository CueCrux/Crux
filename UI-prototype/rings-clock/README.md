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
