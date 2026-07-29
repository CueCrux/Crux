#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# crux-deploy.sh — one-shot, operator-run deploy of the Crux Daemon.
#
# Pulls the desired crux-daemon image, recreates the `crux` compose service,
# then gates on a health + smoke probe. If the gate fails it AUTO-ROLLS-BACK to
# the previously-running image id and exits non-zero.
#
# This is ADDITIVE operational tooling. It does NOT change daemon behaviour and
# it NEVER writes secrets: it only pulls images and reads configuration that
# already lives in your committed compose file / its env_file. Run it manually
# or from cron; it is idempotent w.r.t. a no-op (re-pull + recreate).
#
# Environment variables:
#   CRUX_COMPOSE_FILE   Path to the compose file. Default: ./docker-compose.yml
#   CRUX_IMAGE_TAG      Image tag to deploy. Default: edge
#   CRUX_SERVICE        Compose service name. Default: crux
#   CRUX_HEALTH_URL     readyz URL.   Default: http://127.0.0.1:14800/readyz
#   CRUX_VERSION_URL    version URL.  Default: http://127.0.0.1:14800/v1/version
#   CRUX_HEALTH_TIMEOUT Seconds to wait for readyz. Default: 30
#   CRUX_IMAGE          Image repo. Default: ghcr.io/cuecrux/crux-daemon
#
# Requirements: docker (with the `docker compose` plugin) and curl.

set -euo pipefail

# ── Configuration (env-overridable) ─────────────────────────────────
COMPOSE_FILE="${CRUX_COMPOSE_FILE:-./docker-compose.yml}"
IMAGE_TAG="${CRUX_IMAGE_TAG:-edge}"
SERVICE="${CRUX_SERVICE:-crux}"
IMAGE="${CRUX_IMAGE:-ghcr.io/cuecrux/crux-daemon}"
HEALTH_URL="${CRUX_HEALTH_URL:-http://127.0.0.1:14800/readyz}"
VERSION_URL="${CRUX_VERSION_URL:-http://127.0.0.1:14800/v1/version}"
HEALTH_TIMEOUT="${CRUX_HEALTH_TIMEOUT:-30}"

log()  { printf '[crux-deploy] %s\n' "$*"; }
err()  { printf '[crux-deploy] ERROR: %s\n' "$*" >&2; }

# ── 1. Pre-flight: required tooling + compose file ──────────────────
command -v docker >/dev/null 2>&1 || { err "docker not found on PATH"; exit 1; }
command -v curl   >/dev/null 2>&1 || { err "curl not found on PATH"; exit 1; }
if ! docker compose version >/dev/null 2>&1; then
  err "'docker compose' plugin not available"; exit 1
fi
if [ ! -f "$COMPOSE_FILE" ]; then
  err "compose file not found: $COMPOSE_FILE"; exit 1
fi

dc() { docker compose -f "$COMPOSE_FILE" "$@"; }

log "compose file : $COMPOSE_FILE"
log "service      : $SERVICE"
log "image        : ${IMAGE}:${IMAGE_TAG}"

# Best-effort: report the version currently serving (skip silently if down).
if cur_ver="$(curl -fsS --max-time 3 "$VERSION_URL" 2>/dev/null)"; then
  log "current /v1/version: $cur_ver"
else
  log "current /v1/version: unreachable (daemon down or not yet deployed) — continuing"
fi

# ── 2. Capture ROLLBACK reference (currently-running image id) ──────
# `docker compose images -q` prints the image id of the running service
# container; fall back to inspecting the container if that yields nothing.
ROLLBACK_IMAGE_ID="$(dc images -q "$SERVICE" 2>/dev/null | head -n1 || true)"
if [ -z "${ROLLBACK_IMAGE_ID:-}" ]; then
  cid="$(dc ps -q "$SERVICE" 2>/dev/null | head -n1 || true)"
  if [ -n "$cid" ]; then
    ROLLBACK_IMAGE_ID="$(docker inspect --format '{{.Image}}' "$cid" 2>/dev/null || true)"
  fi
fi
if [ -n "${ROLLBACK_IMAGE_ID:-}" ]; then
  log "rollback ref : $ROLLBACK_IMAGE_ID (previous running image id)"
else
  log "rollback ref : none (no running '$SERVICE' container — first deploy)"
fi

# Resolve what compose will actually RUN for the service. Override hosts pin a
# locally-built image (e.g. the wolfi `*:local-with-git` git layer built via
# Dockerfile.update-check) that is distinct from the pulled tag — so a plain
# `up` would recreate that STALE local image and silently ignore the pull. We
# detect a service `build:` (json first, yaml fallback) and, when present,
# rebuild the local image from the freshly-pulled base before recreating.
svc_field() {
  dc config --format json 2>/dev/null \
    | SVC="$SERVICE" FIELD="$1" python3 -c 'import json,sys,os
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
s=d.get("services",{}).get(os.environ["SVC"],{})
v=s.get(os.environ["FIELD"])
print(v if isinstance(v,str) else ("1" if v else ""))' 2>/dev/null || true
}
SERVICE_IMAGE="$(svc_field image)"
SERVICE_HAS_BUILD="$(svc_field build)"
# Fallback when `config --format json` is unavailable: treat the documented
# wolfi override (`*:local-with-git`) as a locally-built service.
if [ -z "$SERVICE_HAS_BUILD" ] && dc config 2>/dev/null | grep -q 'local-with-git'; then
  SERVICE_HAS_BUILD=1
  [ -n "$SERVICE_IMAGE" ] || SERVICE_IMAGE="$(dc config 2>/dev/null | grep -oE '[^[:space:]]*crux-daemon:local-with-git' | head -n1 || true)"
fi

# ── 3. Pull the target image and (re)create the service ─────────────
log "pulling ${IMAGE}:${IMAGE_TAG} ..."
if ! docker pull "${IMAGE}:${IMAGE_TAG}"; then
  err "docker pull failed for ${IMAGE}:${IMAGE_TAG}"; exit 1
fi

if [ -n "$SERVICE_HAS_BUILD" ]; then
  log "override host: '$SERVICE' runs a locally-built image (${SERVICE_IMAGE:-?}) — retag pulled base to :latest + rebuild"
  # The local build's FROM is the repo's `:latest`; point it at the exact pulled tag.
  docker tag "${IMAGE}:${IMAGE_TAG}" "${IMAGE}:latest" 2>/dev/null || true
  if ! dc build "$SERVICE"; then err "'docker compose build $SERVICE' failed"; exit 1; fi
fi

log "starting '$SERVICE' ..."
if ! dc up -d "$SERVICE"; then
  err "'docker compose up -d $SERVICE' failed"
  # The up failed; the prior container may still be running. Do not blow it away.
  exit 1
fi

# ── Rollback helper ─────────────────────────────────────────────────
rollback() {
  if [ -z "${ROLLBACK_IMAGE_ID:-}" ]; then
    err "health gate failed and no rollback image is available — leaving service as-is for inspection"
    return 1
  fi
  err "health gate failed — rolling back to $ROLLBACK_IMAGE_ID"
  # Re-tag the previous image to the name compose actually RUNS (the locally
  # pinned image on override hosts, else the deploy tag), then recreate on it.
  rb_target="${IMAGE}:${IMAGE_TAG}"
  if [ -n "$SERVICE_HAS_BUILD" ] && [ -n "$SERVICE_IMAGE" ]; then rb_target="$SERVICE_IMAGE"; fi
  if docker tag "$ROLLBACK_IMAGE_ID" "$rb_target" \
     && dc up -d --force-recreate "$SERVICE"; then
    err "rollback complete — '$SERVICE' restored to previous image $ROLLBACK_IMAGE_ID"
  else
    err "rollback FAILED — manual intervention required (previous image id: $ROLLBACK_IMAGE_ID)"
  fi
  return 1
}

# ── 4. Health gate: poll readyz for up to HEALTH_TIMEOUT seconds ────
log "waiting up to ${HEALTH_TIMEOUT}s for readyz at $HEALTH_URL ..."
healthy=0
elapsed=0
while [ "$elapsed" -lt "$HEALTH_TIMEOUT" ]; do
  if curl -fsS --max-time 3 "$HEALTH_URL" >/dev/null 2>&1; then
    healthy=1
    break
  fi
  sleep 2
  elapsed=$((elapsed + 2))
done

if [ "$healthy" -ne 1 ]; then
  err "readyz did not pass within ${HEALTH_TIMEOUT}s"
  rollback || true
  exit 1
fi
log "readyz OK after ~${elapsed}s"

# ── 5. Smoke probe: /v1/version must respond and parse ──────────────
if ! new_ver="$(curl -fsS --max-time 5 "$VERSION_URL" 2>/dev/null)"; then
  err "smoke probe failed: $VERSION_URL unreachable"
  rollback || true
  exit 1
fi
# Validate it parses as JSON containing a version field. Prefer a JSON parser
# when available; fall back to a permissive grep so the script keeps no exotic deps.
parsed=0
if command -v python3 >/dev/null 2>&1; then
  if printf '%s' "$new_ver" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("version") else 1)' 2>/dev/null; then
    parsed=1
  fi
elif command -v jq >/dev/null 2>&1; then
  if printf '%s' "$new_ver" | jq -e '.version' >/dev/null 2>&1; then
    parsed=1
  fi
else
  case "$new_ver" in
    *'"version"'*) parsed=1 ;;
  esac
fi

if [ "$parsed" -ne 1 ]; then
  err "smoke probe response did not parse / missing 'version' field: $new_ver"
  rollback || true
  exit 1
fi

# ── 6. Success ──────────────────────────────────────────────────────
log "deploy OK — /v1/version now reports: $new_ver"
exit 0
