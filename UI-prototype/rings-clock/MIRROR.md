# Crux prod-mirror — local daemon against a copy of production data

A throwaway, read-write **copy** of the production Crux daemon (`corecruxd`) running
locally, backed by a **duplicate** of the prod data volume. Used to preview console
+ daemon changes against real prod-shaped data without touching production.

> **Two runtimes, one data copy, one review URL (`127.0.0.1:14802`):**
>
> 1. **Primary (current): the branch-built binary as a host process** —
>    `run-branch-mirror.sh` / `stop-branch-mirror.sh`. Runs
>    `target/release/corecruxd` from this checkout against the data copy, so the
>    branch's new **daemon** routes (M1 `/v1/facts/list`, M5 cost persistence, M6
>    `/v1/receipts/list` + identity propose) are live at the same review URL. This
>    is what the `console-surfaces-remediation` milestones were verified against.
> 2. **Rollback: the prod-image container** (`crux-mirror`, `docker run …`). The
>    exact prod binary (`docker save | docker load`), for A/B against prod
>    behaviour. Currently **stopped** — `stop-branch-mirror.sh` frees the port,
>    then `docker start crux-mirror` restores the prod-binary runtime.
>
> Only ONE may own `127.0.0.1:14802` at a time. Both share the same
> `/home/myles/crux-prod-mirror/data` copy (additive schema — the branch binary
> boots clean on 0.5.48-written data).

> **Production is read-only.** Nothing here mutates prod. The data is a one-shot
> `tar` stream from a `:ro` throwaway container off the prod volume; the image is a
> `docker save | docker load` of the exact prod image. No prod container/file/volume
> is ever stopped, restarted, or written. The branch binary is built locally from
> source — it never reaches prod.

## What it is

| Thing | Value |
|---|---|
| Container name | `crux-mirror` |
| Host port | `127.0.0.1:14802` → container `14800` (HTTP) |
| Image | `cuecrux/crux-daemon:local-with-git` (image id `0082d2a74cd7`, prod digest `sha256:0082d2a74cd75c0115d952f7d90a013a88e454a1bcc20fc631eda0f01e33d784`; also tagged `ghcr.io/cuecrux/crux-daemon:latest` on prod) |
| Image provenance | `ssh root@crux "docker save cuecrux/crux-daemon:local-with-git" \| docker load` (the exact prod binary; NOT built from source) |
| Data snapshot | `2026-07-22T20:47Z`, 1.1 GB, whole volume copied (nothing skipped) |
| Data source | prod docker volume `crux_crux-data` on host `crux` (Tailscale `100.70.12.73`) |
| Runs as | `--user 1000:1000` (the copied data is owned by local uid 1000; the image default user is uid 65532 which cannot write the host-owned copy) |

Staging (all OUTSIDE the repo, never committed): `/home/myles/crux-prod-mirror/`
- `data/` — the duplicated prod data volume (rw copy).
- `crux.env` — **secrets** copied from prod `/root/.config/cuecrux/crux.env` (HS256 JWT secret, agent tokens). `chmod 600`. **Never commit.**
- `override.env` — non-secret env extracted from prod `docker-compose.override.yml` (feature flags, `jwt_hs256` auth mode, iss/aud).
- `mirror.env` — mirror-only overrides (data dir, console dev path, safety toggles). Loaded LAST so it wins.
- `shots/` — Playwright screenshots. `rings-verify.mjs` — the verification script.

## Env parity + safety deviations from prod

Auth is replicated exactly (`CORECRUXD_AUTH_MODE=jwt_hs256`, `CORECRUXD_JWT_ISS=cuecrux-crux-mint`,
`CORECRUXD_JWT_AUD=crux.cuecrux.com`, plus the HS256 secret + static agent tokens from
`crux.env`), so the local `$CRUX_AGENT_TOKEN` from `~/.config/cuecrux/env` validates
against the mirror just like against prod.

`mirror.env` deliberately differs from prod to keep the mirror inert:
- `CORECRUXD_USAGE_RECEIPTS_SUBMIT=0` + `CORECRUXD_USAGE_RECEIPTS_CONSENT_AT=` — a mirror must NOT phone home to `ingest.cuecrux.com`.
- `CORECRUXD_UPDATE_CHECK_ENABLED=0`, `CORECRUXD_ENGINE_BASE_URL=` — no external git/engine reach-out.
- `CORECRUXD_CONSOLE_DEV_PATH=/console-dev` — hot-serve the modified console from the bind-mounted repo dir (see below).

The prod-parity ExecPlan work board (`/v1/work?source=all` ≈ 1000+ items) needs the
operator's ExecPlan tree, which lives OUTSIDE the data volume (in the operator's
private planning checkout, not this repo). It is bind-mounted **read-only** from the
local workstation tree (prod projects the same tree, rsynced from here):
- `<planning-checkout>/.agent/execplans` → `/srv/execplans:ro` (`CRUX_EXECPLANS_ROOT`)
- `<planning-checkout>/docs/master-plan/tracking` → `/srv/tracking:ro` (`CRUX_OPEN_DECISIONS_PATH`)

## Console dev override (why no rebuild is needed)

`corecruxd` embeds the console via `include_str!` (compile-time), but
`crates/corecruxd/src/console.rs` honours `CORECRUXD_CONSOLE_DEV_PATH`: when set, it
hot-serves `v2/shell.html`, `v2/pages.js`, `v2/render.js`, `v2/api.js` and `assets/*`
from `<dev>/v2/…` on disk (see `console_v2_dev_override` / `serve_console_v2_asset`).
So mounting the repo's `crates/corecruxd/console` dir at `/console-dev` and pointing
the env there serves this branch's console edits with **no image rebuild**. The dev
path also injects `window.__CRUX_CONSOLE_DEV__=1`, which disables the PWA service
worker so edits show on a plain refresh.

## Primary runtime: the branch-built binary (host process)

`console-surfaces-remediation` adds **daemon** routes (M1/M5/M6), and the console
dev-path override only hot-serves JS — a new Rust route needs the branch binary
running. Rather than rebuild the container image every milestone, the mirror runs
the locally-built `corecruxd` directly as a host process on the same review URL:

```bash
cd /home/myles/CueCrux/Crux
cargo build --release -p corecruxd            # produce target/release/corecruxd
/home/myles/crux-prod-mirror/run-branch-mirror.sh   # launch on 127.0.0.1:14802
# ... review at http://127.0.0.1:14802/console ...
/home/myles/crux-prod-mirror/stop-branch-mirror.sh  # graceful SIGTERM (SIGKILL after 10s)
```

- **`run-branch-mirror.sh`** launches `target/release/corecruxd` with the WSL-tested
  detach triad (`setsid + nohup + </dev/null + disown`), waits on `/readyz`, and
  writes the authoritative pid to `branch-mirror.pid`; log at `branch-mirror.log`.
  Ports: HTTP `14802`, gRPC `14807`, MCP `14811`. `CORECRUXD_DATA_DIR` points at the
  same `data/` copy.
- **`stop-branch-mirror.sh`** SIGTERMs the pid, waits up to 10s, only then SIGKILL
  (never `-9` a partially-flushed writer without a clean-shutdown chance first).
- **Env**: the script sources `override.env` + `mirror.env` (non-secret) and then
  applies host overrides. It deliberately **never sources `crux.env`** — the branch
  mirror runs `CORECRUXD_AUTH_MODE=off` on loopback only, so no secret is read.
- **Rollback to the prod binary**: `stop-branch-mirror.sh` (frees `14802`), then
  `docker start crux-mirror`. See "Run / refresh / stop" (container) below.

### `CORECRUXD_IDENTITY_LINKS=1` (mirror only)

`run-branch-mirror.sh` sets `CORECRUXD_IDENTITY_LINKS=1` so `cx-identity` is
reviewable — it un-404s `GET /v1/identity/candidates` and enables the M6 seed path
`POST /v1/identity/candidates/propose`. **This is a MIRROR-ONLY review toggle.** The
prod flag state is a deliberate **M9 operator decision** and is NOT set by anything
that reaches production. (On this data the honest candidate yield is 0 — the page
renders its help panel + seed action, not fabricated candidates.)

### M6 demo artifacts on the data copy (throwaway — ignore for prod parity)

To exercise the M6 verbatim gate-receipt verification + pending-gates paths, the
data copy carries a small set of **minted throwaway artifacts**:

- project **`m6-demo`** ("M6 demo project") with 2 work items
  (`M6 pending-gate demo`, `M6 receipt-verification demo`),
- passport **`m6-gate-approver`**,
- **1 approved + 1 pending** gate (the pending one is what `cx-gates` lists as
  `1 pending`, and the approved one backs a fetchable `ad_ga_*` gate receipt).

These live ONLY in the local data copy — **purge/ignore them before any
prod-parity comparison**; they are not on prod. They are the reason `cx-gates`
shows `1 pending` and the receipts list carries fetchable `ad_ga_*` rows on the
mirror.

### `populate-cost.sh` — one-shot cost attribution seed

`GET /v1/cost/report` + work-item `token_burn` read a store fed only by
`POST /v1/cost/report` (see the token_burn section below). `populate-cost.sh`
runs `corecruxctl session cost` over the local Claude Code transcripts, strips the
only content-bearing field (`top_blocks=[]`) with a content-guard, and POSTs the
numeric/metadata skeleton:

```bash
MIRROR_BASE=http://127.0.0.1:14802 /home/myles/crux-prod-mirror/populate-cost.sh
```

On this data it posts 828 transcripts → 83 distinct sessions and stamps
`token_burn` on 390 / 1082 work items. **Since M5 made the store restart-durable
(journal + boot replay), this only needs to run ONCE** — the branch binary replays
`<data_dir>/cost/reports.jsonl` on boot instead of re-posting.

## Recreate from scratch (prod-image container — rollback path)

```bash
# 0. Prereqs: `ssh root@crux` works; local docker; ~/.config/cuecrux/env has the token.
mkdir -p /home/myles/crux-prod-mirror/{data,shots}

# 1. Duplicate the prod data volume (read-only source; ~1.1 GB).
ssh root@crux "docker run --rm -v crux_crux-data:/data:ro alpine tar cz -C /data ." \
  | tar xz -C /home/myles/crux-prod-mirror/data

# 2. Load the exact prod image locally.
ssh root@crux "docker save cuecrux/crux-daemon:local-with-git" | docker load

# 3. Copy the prod env (SECRETS — stays in staging, never committed).
scp root@crux:/root/.config/cuecrux/crux.env /home/myles/crux-prod-mirror/crux.env
chmod 600 /home/myles/crux-prod-mirror/crux.env
#    override.env + mirror.env are already in staging (see this dir); regenerate
#    override.env from /opt/crux/docker-compose.override.yml if prod flags change.

# 4. Run the mirror (see below).
```

## Run / refresh / stop (prod-image container — rollback path)

> The container is the **rollback** runtime (exact prod binary). For day-to-day
> review of this branch use `run-branch-mirror.sh` (above). The container is
> currently stopped; only start it when you need to A/B against prod behaviour, and
> stop the branch binary first so the port is free.

```bash
# RUN (or refresh after console edits — just recreate; the console is bind-mounted).
docker rm -f crux-mirror 2>/dev/null
docker run -d --name crux-mirror \
  --user 1000:1000 \
  -p 127.0.0.1:14802:14800 \
  -v /home/myles/crux-prod-mirror/data:/data \
  -v /home/myles/CueCrux/Crux/crates/corecruxd/console:/console-dev:ro \
  -v "$PLANNING_CHECKOUT/.agent/execplans":/srv/execplans:ro \
  -v "$PLANNING_CHECKOUT/docs/master-plan/tracking":/srv/tracking:ro \
  --env-file /home/myles/crux-prod-mirror/crux.env \
  --env-file /home/myles/crux-prod-mirror/override.env \
  --env-file /home/myles/crux-prod-mirror/mirror.env \
  cuecrux/crux-daemon:local-with-git

# Console edits are picked up on browser refresh (no restart needed — bind mount +
# dev override). A daemon restart is only needed for env changes.

# STOP (safe — data persists in the staging copy).
docker stop crux-mirror

# REMOVE (data copy on disk is untouched).
docker rm -f crux-mirror

# REFRESH DATA to a newer prod snapshot: stop, re-run step 1 into an empty data/, run.
```

## Verify

```bash
source ~/.config/cuecrux/env       # $CRUX_AGENT_TOKEN
curl -s http://127.0.0.1:14802/readyz                    # -> {"ok":true}
curl -s "http://127.0.0.1:14802/v1/work?source=all" \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["count"])'   # -> ~1000+
# Console: http://127.0.0.1:14802/console  (default = Overwatch, rail collapsed,
# "Rings" entry -> #/rings renders the native clock-of-work canvas, no iframe).
```

Screenshot proof (Playwright-in-Docker). **`--network=host` is broken on this host**
— a host-network container cannot reach the daemon's `127.0.0.1:14802` loopback
bind. Use the **TCP-proxy pattern** instead: a tiny host forwarder republishes the
loopback port on `0.0.0.0:14899`, and the container reaches it via
`host.docker.internal`.

```bash
# 1. Start the forwarder on the host (0.0.0.0:14899 -> 127.0.0.1:14802).
#    scratchpad/tcp_proxy.py is a ~40-line asyncio forwarder; background it:
setsid nohup python3 tcp_proxy.py >proxy.log 2>&1 </dev/null &

# 2. Run Playwright, pointing MIRROR_BASE at the proxy via the docker gateway.
cd /home/myles/crux-prod-mirror
docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -e MIRROR_BASE="http://host.docker.internal:14899" \
  -v "$PWD:/work" -w /work \
  mcr.microsoft.com/playwright:v1.49.0-noble \
  bash -c "npm i -s playwright@1.49.0 >/dev/null 2>&1 && node m9-sweep.mjs"
# -> shots/m9-after/00..12-*.png (13 surfaces; every mN-verify.mjs uses this pattern)

# 3. STOP the proxy when done (leaving 0.0.0.0:14899 open is a needless exposure).
pkill -f tcp_proxy.py
```

The verify scripts read `MIRROR_BASE` (default `http://127.0.0.1:14802`) precisely
so the same script runs directly on the host or through the proxy from a container.

## Safety rules (recap)

- Prod is **read-only**: only `ssh root@crux` read commands + `:ro` throwaway containers.
- Secrets live ONLY in `/home/myles/crux-prod-mirror/*.env` (staging). Never commit them; never `cat` them into a repo file.
- The mirror does not submit usage receipts, run update checks, or reach the external engine.

## Rings console page — NATIVE (no longer embeds the mock)

**As of console-surfaces-remediation M10 the Rings page is native — the console
no longer embeds `console-mock.html`.** There is no `RINGS_HTML_B64` blob and no
iframe anymore. The `#/rings` page is rendered directly into `#content` by:

- **`crates/corecruxd/console/v2/render.js`** — `renderRings(container, ctx)`:
  the canvas "clock of work" engine (ported from the mock), the lens tiles /
  glance / control bar / detail pane built with `el()`/`svgEl()` safe
  construction (no raw HTML strings), all data loaded through the console's
  `CruxApi` client via `fetchJSON` (`/v1/work?source=all`,
  `/v1/console/summary`, and a `/v1/facts/list` cursor walk), with the embedded
  snapshots (`RINGS_PLANS_RAW` / `RINGS_GRAPH_RAW` / `RINGS_RFACTS`) as honest
  degradation when a feed is absent. The RAF loop, resize/intersection
  observers and document/window listeners are torn down when the canvas leaves
  the DOM (route change) — self-cancelled via an `isConnected` check plus a
  module-scope cleanup handle re-run on re-entry.
- **`crates/corecruxd/console/v2/shell.html`** — the `.rings-root`-scoped CSS
  (dark-fixed canvas identity mapped onto `--rings-*` custom properties; fonts
  alias the theme-stable console `--font-*` tokens) and the `renderDestination`
  `rings` branch that flex-fills the viewport below the topbar and calls
  `window.CruxRender.renderRings`.

**`UI-prototype/rings-clock/console-mock.html` remains a standalone prototype /
artifact source** — it is the design reference the native port was ported from,
and it still works on its own (open the file, or publish it as an artifact). It
is **no longer wired into the console**, so editing it does **not** change the
console: to change the live Rings page, edit `renderRings` in `render.js` (JS)
and the `.rings-root` CSS in `shell.html`. The mirror mounts the console dir
(`CORECRUXD_CONSOLE_DEV_PATH=/console-dev`), so a browser refresh picks those
edits up — no container restart needed.

## Auth workaround (local browser access)

Prod fronts the console with an oauth2 proxy (`/oauth2/sign_in`) that does not
exist locally, so the replicated `jwt_hs256` mode left the browser session-less
("Your session has expired") with a dead sign-in link. The mirror now runs with
(in `mirror.env`, which is the LAST `--env-file` and therefore wins):

```
CORECRUXD_AUTH_MODE=off
CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND=1   # container binds 0.0.0.0 internally;
                                           # published on host loopback only
```

This is acceptable ONLY because the container is published on `127.0.0.1` and
runs against a throwaway copy. Never carry these two lines to any non-loopback
deployment. API calls need no Authorization header against the mirror.

## token_burn is null — ROOT CAUSE + FIX (console-surfaces-remediation M5)

**Root cause (definitive).** `/v1/work` `token_burn` and `/v1/cost/report` both
read a **process-global, in-memory** cost store (`corecruxd/src/cost.rs`,
`OnceLock<Mutex<CostStore>>` — "pure in-memory, no disk"). That store is
populated **only** by `POST /v1/cost/report`, which `corecruxctl session cost
--post` sends after parsing the operator's **local** Claude Code transcripts
(the daemon never sees a transcript). So a fresh daemon process has an **empty**
store and returns `token_burn: null` / `has_report: false` until reports are
(re-)posted. It was never about the copied data volume — the mirror nulled
because it was a fresh process with nothing posted. **This empties prod too on
any restart**, until the SessionEnd hook / `cost-sweep` re-posts.

**Fix (this branch).** `cost.rs` now journals every accepted POST to an
append-only `<data_dir>/cost/reports.jsonl` and **replays it into the store at
startup** (latest line per `(tenant, session)` wins — same semantics the store
already had). Enabled only when `CORECRUXD_FEATURE_COST_LENS` is on; no config,
no compaction (tiny file), malformed lines are warn+skipped. So cost attribution
now **survives a restart** — posted once, it persists. `GET /v1/cost/report`'s
`sessions[]` picker was also extended (additive) with the window
(`started_at`/`ended_at`), `context_tokens`, `output_tokens`, `actor_passport`,
and `execplan_slugs` the `cx-cost` sessions×burn page renders.

**Populate the mirror** (`/home/myles/crux-prod-mirror/populate-cost.sh`):

```bash
MIRROR_BASE=http://127.0.0.1:14802 ./populate-cost.sh
```

It runs `corecruxctl session cost --file <t> --json` over every transcript under
`~/.claude/projects`, **strips the only content-bearing field** before posting,
and POSTs the numeric/metadata skeleton. **Privacy:** the `CostReport` is mostly
token counts / windows / plan metadata, but `top_blocks[].preview` carries
≤80-char excerpts of tool results / user prompts / assistant prose (thinking is
redacted). The M5 privacy gate forbids posting conversation content **anywhere**,
so the script sets `top_blocks = []` (jq) — retaining headline / measured /
window / `execplan_slugs` / buckets (coarse tags) / levers (advice + tool names),
which is everything the page and `token_burn` attribution need — and a
content-guard refuses to post if any preview survives the strip. Verified: the
on-disk journal has **0** non-empty `top_blocks` / **0** `preview` keys — zero
conversation content at rest.

After M5's persistence lands, the script only needs to run **once** — a mirror
(or prod) restart replays the journal instead of re-posting. On this data it
posts 828 transcripts → 83 distinct sessions (latest-wins) and stamps
`token_burn` on **390 / 1082** work items (link 22 · mixed 27 · window 341).

## Paged facts listing — RESOLVED on `console-surfaces-remediation` (M1)

> **Was a known gap; now fixed on this branch.** Previously the store held
> thousands of visible facts but no HTTP surface could enumerate them:
> `/v1/console/facts` returned only the ~26–55 visible facts inside a filtered
> recent-200 window (`as_of_unix_ms` filtered that same window — page 2 was empty,
> not a pager) and `/v1/facts` is recall/budget-shaped (query-driven).

M1 adds **`GET /v1/facts/list`** (`crates/corecruxd/src/http/facts.rs`): a stable
`(stored_at_ms, fact_id)` DESC listing over the fact-store journal with opaque
cursor pagination (`cursor="<stored_at_ms>:<fact_id>"`), server-side
private/reserved filtering (reserved prefixes reused from
`crux_mcp::tools::memory::RESERVED_ENTITY_PREFIXES`), and per-fact fields the
console needs (fact_id, entity, key, value + full-length, confidence,
horizon_class, actor, stored_at, tokens, version, `superseded_by`). On the mirror
it enumerates the full store — **3,611 visible / 5,063 stored** — across cursor
pages with 0 dupes/omissions.

Consumers rewired to it (M2): `cx-facts` (`#/memory/cx-facts`) now pages the whole
store with a search box + `as_of` field and a `N of TOTAL` header; the Rings
data-graph lens uses the same route (its old "N of 5,026" cap is gone). Verified on
the branch binary at `127.0.0.1:14802`.
