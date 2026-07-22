# Crux prod-mirror — local daemon against a copy of production data

A throwaway, read-write **copy** of the production Crux daemon (`corecruxd`) running
locally in Docker, backed by a **duplicate** of the prod data volume. Used to preview
console changes (e.g. the `Rings` prototype page) against real prod-shaped data
without touching production.

> **Production is read-only.** Nothing here mutates prod. The data is a one-shot
> `tar` stream from a `:ro` throwaway container off the prod volume; the image is a
> `docker save | docker load` of the exact prod image. No prod container/file/volume
> is ever stopped, restarted, or written.

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
PlanCrux ExecPlan tree, which lives OUTSIDE the data volume. It is bind-mounted
**read-only** from the local workstation tree (prod projects the same tree, rsynced
from here):
- `/home/myles/CueCrux/PlanCrux/.agent/execplans` → `/srv/plancrux-execplans:ro` (`CRUX_EXECPLANS_ROOT`)
- `/home/myles/CueCrux/PlanCrux/docs/master-plan/tracking` → `/srv/plancrux-tracking:ro` (`CRUX_OPEN_DECISIONS_PATH`)

## Console dev override (why no rebuild is needed)

`corecruxd` embeds the console via `include_str!` (compile-time), but
`crates/corecruxd/src/console.rs` honours `CORECRUXD_CONSOLE_DEV_PATH`: when set, it
hot-serves `v2/shell.html`, `v2/pages.js`, `v2/render.js`, `v2/api.js` and `assets/*`
from `<dev>/v2/…` on disk (see `console_v2_dev_override` / `serve_console_v2_asset`).
So mounting the repo's `crates/corecruxd/console` dir at `/console-dev` and pointing
the env there serves this branch's console edits with **no image rebuild**. The dev
path also injects `window.__CRUX_CONSOLE_DEV__=1`, which disables the PWA service
worker so edits show on a plain refresh.

## Recreate from scratch

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

## Run / refresh / stop

```bash
# RUN (or refresh after console edits — just recreate; the console is bind-mounted).
docker rm -f crux-mirror 2>/dev/null
docker run -d --name crux-mirror \
  --user 1000:1000 \
  -p 127.0.0.1:14802:14800 \
  -v /home/myles/crux-prod-mirror/data:/data \
  -v /home/myles/CueCrux/Crux/crates/corecruxd/console:/console-dev:ro \
  -v /home/myles/CueCrux/PlanCrux/.agent/execplans:/srv/plancrux-execplans:ro \
  -v /home/myles/CueCrux/PlanCrux/docs/master-plan/tracking:/srv/plancrux-tracking:ro \
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
# new "Rings" entry -> #/rings renders the mock in an iframe).
```

Screenshot proof (Playwright-in-Docker, `--network=host` for loopback):

```bash
cd /home/myles/crux-prod-mirror
docker run --rm --network=host -e CRUX_TOKEN="$CRUX_AGENT_TOKEN" -v "$PWD:/work" -w /work \
  mcr.microsoft.com/playwright:v1.49.0-noble \
  bash -c "npm i -s playwright@1.49.0 >/dev/null 2>&1 && node rings-verify.mjs"
# -> shots/01-default-overwatch-collapsed.png, 02-rings-page.png, 03-rings-rail-expanded.png
```

## Safety rules (recap)

- Prod is **read-only**: only `ssh root@crux` read commands + `:ro` throwaway containers.
- Secrets live ONLY in `/home/myles/crux-prod-mirror/*.env` (staging). Never commit them; never `cat` them into a repo file.
- The mirror does not submit usage receipts, run update checks, or reach the external engine.
