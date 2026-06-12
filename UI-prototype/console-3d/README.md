# Crux Substrate — 3D console concept

A design-first reimagining of the Crux daemon `/console` as a **spatial substrate**:
one navigable clay-render world instead of twelve panels. Layout language borrowed from
[vectrfl.com](https://www.vectrfl.com/) (soft isometric clay world, scroll-driven camera
dolly, numbered chapter rail, glowing data beams, dotted ripple fields) and re-grounded
in the daemon's actual object model.

Sibling: `../agent-observability.html` — the 2D Miller-columns prototype (now the shipped
console playground); this concept reuses its dummy-data lineage and design tokens.

## Run it

```bash
./serve.sh          # → http://localhost:8321/
```

(Any static server works — ES modules need HTTP, not file://.)

## The idea

Every node shares **one block form** — plinth + rectangular slab, label printed flat on
the top face, status lamp on the corner (pulses while `run`):

| Daemon object | Block treatment |
|---|---|
| daemon core | bigger block at the origin; the passport grid wires straight into it |
| execplan | stacked block — one slab per milestone, slab tint = gate state (done/in-progress/blocked/planned) |
| session / passport / fact / receipt / coord / punchcard | single slab, tinted by status; districts are rectangular grid groups |
| link (binds / drives / gates / seals / chain / coord / handoff) | flat L-routed circuit trace on the ground, flowing particles, color by relation |

Clicking a node never moves the camera — it halos the node, pulses its links, pins a
flat **relationship tag** to each of its traces (relation + what it means), and opens
the detail panel. The receipts row reads left→right as the seq 1→5 chain.

The **left district nav** (one icon per panel) lines that panel's nodes up through its
district centre — nodes glide, traces re-route when they settle, the camera flies to
frame the line. Click again (or scroll back into the story) to restore the grid.

**Story mode** — scrolling scrubs a camera dolly through six chapters (rail bottom-left,
Vectr-style): session boots → work is execplans → milestones gate on facts → every
mutation seals a receipt → sessions coordinate → the substrate remembers.

**Console mode** — the end state of the scroll *is* the console: free orbit, click any
node to focus it (camera glide + glass detail panel with fields/doc/linked-node chips),
breadcrumb trail, `Esc` to overview. Clicking works mid-story too — the story is just a
camera path over the live graph.

## Embed mode

`index.html?embed=1&theme=dark|light` — chrome hides, boot lands straight in explore,
and node focus/unfocus round-trips to the HOST page over origin-checked postMessage
(`cx3d:focus` / `cx3d:unfocus` out; `cx3d:focusId` / `cx3d:theme` in). The classic
console embeds it this way via its 2D⇄3D toolbar switch, rendering node detail in its
own right pane.

## Files

```
index.html          chrome + overlay DOM + importmap
css/console3d.css   overlay styles (tokens from the shipped console: Public Sans +
                    JetBrains Mono, glass surfaces, accent #5E6AD2, status palette)
js/data.js          dummy graph: districts, nodes, links, chapters  ← live-wire swap point
js/world.js         three.js scene: clay meshes, edge tubes + particle flow,
                    dot-ripple ground shader, light/dark theming
js/main.js          camera rig (scroll scrub ↔ orbit ↔ focus), raycast, panel, labels
vendor/             three.module.min.js r165 + OrbitControls + RoundedBoxGeometry
tools/verify.cjs    headless smoke: loads the page, scrubs the story, focuses a
                    node, toggles dark — screenshots to /tmp/cx3d/ + console-error
                    check (workstation-local paths: Cue's playwright + chromium-1208)
```

## Iterating on the design

- **Palette / mood** — `THEMES` in `js/world.js` (light + dark in one place).
- **World layout** — `DISTRICTS` + per-node `pos` in `js/data.js` (plain `[x, z]` coords).
- **Story** — `CHAPTERS` in `js/data.js`: copy, camera keyframes (`cam.pos`/`cam.look`),
  which nodes halo (`focus`), which beams pulse (`beams`).
- **Node shapes** — `_k_<kind>` builders in `js/world.js`.
- **Overlay chrome** — `css/console3d.css` (hero, rail, panel, pills).

Design intents to honour while iterating:

- Calm by default: the world is still; only status lamps, beams and the focus ripple move.
- No postprocessing: glow = additive sprites + emissive accents (runs on integrated GPUs).
- Text is DOM, not texture: crisp, selectable, themable, accessible.
- `prefers-reduced-motion`: no autoplay shimmer, instant camera cuts.
- Light clay is the default face; dark mirrors the shipped console theme.

## Wiring it live (later, out of scope here)

`js/data.js` is the only data surface. The projection sources already exist:
`/v1/work?source=all` (execplans + states), `/v1/coord/active` (live board),
`/v1/facts` (gate/decision/bench facts), `/v1/receipts/{id}(/verification)` (chain),
session/passport from the boot banner surface. Map those into `NODES`/`LINKS` and the
world renders the real substrate.
