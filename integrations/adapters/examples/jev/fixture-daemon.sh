#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# Local fixture corecruxd for the Jev decision-receipt recipe / e2e tests.
#
#   fixture-daemon.sh start|stop|status
#
# - loopback only, non-default ports (HTTP 24800, gRPC 24007; MCP disabled)
# - CORECRUXD_STREAM_RECEIPTS=1 so POST /v1/mediation/receipts lifts
#   model_invocation drafts into signed receipts
# - CORECRUXD_CONTEXT_SURFACE=1 so the Jev adapter can build state from
#   GET /v1/context (needs query:read)
# - auth: jwt_hs256 with a per-fixture random secret; start registers the
#   passport "jev-agent" (category work) and mints ONE token for it carrying
#   only the scopes the receipt path needs (see SCOPES below)
# - no phone-home: scrubbed env (nothing inherited), passport claim + update
#   check off
# - no secret ever sits in an argv (ps-visible): the HS256 secret reaches the
#   daemon only through its environment, the admin JWT reaches curl through a
#   0600 header file
# - the pidfile records "<pid> <start time>" (/proc/<pid>/stat field 22);
#   stop kills only a PID whose start time and cwd still match, so a rebuilt
#   binary or a different CORECRUXD_BIN cannot orphan the daemon. A live PID
#   that cannot be proven ours is never killed and its pidfile is kept.
#
# Env: CORECRUXD_BIN (default: corecruxd on PATH), JEV_FIXTURE_DIR
# (default: ${TMPDIR:-/tmp}/jev-crux-fixture), JEV_FIXTURE_HTTP_PORT,
# JEV_FIXTURE_GRPC_PORT, JEV_FIXTURE_TOKEN_TTL_SECS (default 604800).
#
# Outputs under $JEV_FIXTURE_DIR: token (0600, bearer JWT), fixture.env
# (non-secret: base URL, tenant, token path, passport), daemon.pub.pem
# (daemon receipt-signing public key), daemon.log, corecruxd.pid.
set -euo pipefail

BIN="${CORECRUXD_BIN:-$(command -v corecruxd || true)}"
FIX="${JEV_FIXTURE_DIR:-${TMPDIR:-/tmp}/jev-crux-fixture}"
HTTP_PORT="${JEV_FIXTURE_HTTP_PORT:-24800}"
GRPC_PORT="${JEV_FIXTURE_GRPC_PORT:-24007}"
MCP_PORT="${JEV_FIXTURE_MCP_PORT:-24801}" # bound only if MCP is re-enabled
TTL="${JEV_FIXTURE_TOKEN_TTL_SECS:-604800}"
PIDFILE="$FIX/corecruxd.pid"
BASE="http://127.0.0.1:$HTTP_PORT"
# Stream receipts mint under tenant "local" (stream_receipts.rs), and the
# verification route re-gates on the receipt's own tenant, so the token is
# scoped to exactly that one tenant.
TENANT="local"
# sessions:write  -> mediation handler (require_session_write_ctx)
# facts:write     -> /v1/mediation/* route gate + PUT /v1/facts
# query:read      -> GET /v1/facts*, GET /v1/observations/aggregate
# receipts:read   -> GET /v1/receipts/{id}/verification
SCOPES="sessions:write facts:write query:read receipts:read"
PASSPORT="jev-agent"
ISS="jev-fixture"
AUD="corecrux-fixture"

die() { echo "fixture: $*" >&2; exit 1; }

# Start time of a PID in clock ticks since boot (/proc/<pid>/stat field 22).
# comm (field 2) may contain spaces, so count from the last ')'.
proc_start() {
  local stat f
  stat="$(cat "/proc/$1/stat" 2>/dev/null)" || return 1
  read -ra f <<< "${stat##*) }"
  echo "${f[19]}"
}

# Prints the pidfile PID. Returns 0 if it is alive and provably ours (same
# start time as recorded at launch, cwd still $FIX), 1 if there is no
# pidfile or the PID is dead, 2 if it is alive but not provably ours.
pidfile_pid() {
  [ -f "$PIDFILE" ] || return 1
  local pid start
  read -r pid start < "$PIDFILE" || true
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  [ -d "/proc/$pid" ] || return 1
  echo "$pid"
  [ -n "$start" ] && [ "$(proc_start "$pid")" = "$start" ] \
    && [ "$(readlink "/proc/$pid/cwd" 2>/dev/null)" = "$(readlink -f "$FIX")" ] || return 2
}

not_ours() {
  die "pidfile $PIDFILE names live pid $1 but it cannot be proven to be this fixture's daemon; pidfile kept, nothing killed. Inspect: ls -l /proc/$1/exe /proc/$1/cwd; if it is the fixture, stop it with: kill $1 && rm $PIDFILE"
}

port_busy() { ss -Hltn "sport = :$1" | grep -q .; }

# mint_jwt <scopes> <ttl_secs>: HS256 JWT on stdout via python3 stdlib. The
# secret is read from its 0600 file and never echoed.
mint_jwt() {
  python3 - "$FIX/jwt.secret" "$1" "$TENANT" "$ISS" "$AUD" "$2" "$PASSPORT" <<'PY2'
import base64, hashlib, hmac, json, sys, time
secret_file, scopes, tenant, iss, aud, ttl, passport = sys.argv[1:]
raw = open(secret_file).read().strip()
key = base64.b64decode(raw[len("base64:"):]) if raw.startswith("base64:") else raw.encode()
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=")
now = int(time.time())
claims = {"sub": passport, "passport_id": passport, "scope": scopes, "tenant_id": tenant,
          "iss": iss, "aud": aud, "iat": now, "exp": now + int(ttl)}
head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
body = b64(json.dumps(claims, separators=(",", ":")).encode())
sig = b64(hmac.new(key, head + b"." + body, hashlib.sha256).digest())
sys.stdout.write((head + b"." + body + b"." + sig).decode())
PY2
}

# Fact writes by a passport-bearing token require a registered passport with a
# category (crux-mcp category_enforce.rs). Register it once with a 60s
# admin:write bootstrap token that only lives in a 0600 header file for the call.
register_passport() {
  local code hdr="$FIX/admin.h"
  # printf is a builtin: the JWT goes straight to the 0600 file, never argv.
  (umask 077; printf 'Authorization: Bearer %s\n' "$(mint_jwt "admin:write" 60)" > "$hdr")
  code="$(curl -s -o "$FIX/passport.create.json" -w '%{http_code}' -X POST "$BASE/v1/passports" \
    -H @"$hdr" -H 'content-type: application/json' \
    --data "{\"id\":\"$PASSPORT\",\"category\":\"work\",\"name\":\"Jev decision recorder (fixture)\"}")" || code=000
  rm -f "$hdr"
  case "$code" in
    201|409) ;;
    *) die "passport registration failed: HTTP $code $(cat "$FIX/passport.create.json")" ;;
  esac
}

# Public verification key for offline checks. Derived here by the key
# custodian from the daemon's local seed (piped, never printed): the HTTP
# surface only exposes it on /v1/admin/version (admin:read). Receipts carry
# key_id = "p_" + blake3(pubkey)[..16], so a verifier can bind this key.
export_pubkey() {
  { printf '302e020100300506032b657004220420'; tr -d '\n ' < "$FIX/data/passport.key"; } \
    | xxd -r -p | openssl pkey -inform DER -pubout -out "$FIX/daemon.pub.pem"
}

cmd_start() {
  [ -x "$BIN" ] || die "corecruxd binary not found (set CORECRUXD_BIN)"
  local pid rc=0
  pid="$(pidfile_pid)" || rc=$?
  case "$rc" in
    0) echo "fixture: already running pid=$pid $BASE"; return 0 ;;
    2) not_ours "$pid" ;;
  esac
  for p in "$HTTP_PORT" "$GRPC_PORT"; do
    port_busy "$p" && die "port $p already in use; set JEV_FIXTURE_*_PORT"
  done
  mkdir -p "$FIX/data" "$FIX/home"
  chmod 700 "$FIX"
  if [ ! -s "$FIX/jwt.secret" ]; then
    (umask 077; printf 'base64:%s\n' "$(openssl rand -base64 48 | tr -d '\n')" > "$FIX/jwt.secret")
  fi

  cd "$FIX"
  # Subshell: un-export everything inherited (no CRUX_AGENT_TOKEN, no sync
  # remotes, no XDG config), export only what the daemon needs, then exec.
  # corecruxd has no *_FILE form of the HS256 secret, so it travels in the
  # environment (readable only by this user), never in an argv. setsid in a
  # non-interactive shell does not fork and the subshell execs it, so $! is
  # the daemon's own PID.
  (
    mapfile -t inherited < <(compgen -e)
    export -n "${inherited[@]}"
    CORECRUXD_JWT_HS256_SECRET="$(cat "$FIX/jwt.secret")"
    export CORECRUXD_JWT_HS256_SECRET \
      PATH=/usr/bin:/bin \
      HOME="$FIX/home" \
      CORECRUXD_DATA_DIR="$FIX/data" \
      CORECRUXD_STATE_DIR="$FIX/data" \
      CORECRUXD_HTTP_HOST=127.0.0.1 CORECRUXD_HTTP_PORT="$HTTP_PORT" \
      CORECRUXD_GRPC_HOST=127.0.0.1 CORECRUXD_GRPC_PORT="$GRPC_PORT" \
      CORECRUXD_MCP_HOST=127.0.0.1 CORECRUXD_MCP_PORT="$MCP_PORT" \
      CORECRUXD_MCP_ENABLED=0 \
      CORECRUXD_AUTH_MODE=jwt_hs256 \
      CORECRUXD_JWT_ISS="$ISS" CORECRUXD_JWT_AUD="$AUD" \
      CORECRUXD_ROUTE_AUTH=enforce \
      CORECRUXD_STREAM_RECEIPTS=1 \
      CORECRUXD_CONTEXT_SURFACE=1 \
      CORECRUXD_PASSPORT_CLAIM_ON_STARTUP=0 \
      CORECRUXD_UPDATE_CHECK_ENABLED=0
    exec setsid "$BIN"
  ) > "$FIX/daemon.log" 2>&1 < /dev/null &
  pid=$!
  disown "$pid" 2>/dev/null || true
  # Start time is fixed at fork, so it is already final before the exec.
  echo "$pid $(proc_start "$pid")" > "$PIDFILE"

  for _ in $(seq 1 120); do
    if curl -sf "$BASE/readyz" >/dev/null 2>&1; then break; fi
    kill -0 "$pid" 2>/dev/null || { tail -n 30 "$FIX/daemon.log" >&2; rm -f "$PIDFILE"; die "daemon exited during startup"; }
    sleep 0.5
  done
  curl -sf "$BASE/readyz" >/dev/null || die "daemon not ready after 60s (pid=$pid, log $FIX/daemon.log)"

  register_passport
  (umask 077; mint_jwt "$SCOPES" "$TTL" > "$FIX/token")
  export_pubkey

  cat > "$FIX/fixture.env" <<EOF
CRUX_BASE_URL=$BASE
CRUX_TENANT=$TENANT
CRUX_TOKEN_FILE=$FIX/token
CRUX_PASSPORT=$PASSPORT
CRUX_DAEMON_PUBKEY_PEM=$FIX/daemon.pub.pem
CRUX_GRPC_ADDR=127.0.0.1:$GRPC_PORT
CRUX_FIXTURE_PID=$pid
EOF
  echo "fixture: started pid=$pid $BASE (auth: Authorization: Bearer \$(cat $FIX/token))"
}

cmd_stop() {
  local pid rc=0
  pid="$(pidfile_pid)" || rc=$?
  case "$rc" in
    1) echo "fixture: not running (no pidfile, or its pid is dead)"; rm -f "$PIDFILE"; return 0 ;;
    2) not_ours "$pid" ;;
  esac
  kill -TERM "$pid"
  for _ in $(seq 1 60); do
    kill -0 "$pid" 2>/dev/null || { rm -f "$PIDFILE"; echo "fixture: stopped pid=$pid"; return 0; }
    sleep 0.5
  done
  die "pid $pid still alive 30s after SIGTERM; not escalating (inspect $FIX/daemon.log)"
}

cmd_status() {
  local pid rc=0
  pid="$(pidfile_pid)" || rc=$?
  case "$rc" in
    1) echo "fixture: stopped"; return 1 ;;
    2) echo "fixture: pidfile pid=$pid is alive but not provably this fixture's daemon" >&2; return 1 ;;
  esac
  local ready=no; curl -sf "$BASE/readyz" >/dev/null 2>&1 && ready=yes
  # Any TCP socket of ours whose peer is not loopback = egress.
  local egress; egress="$(ss -Htnp state established 2>/dev/null | grep "pid=$pid," \
    | awk '{print $4}' | grep -Ev '^(127\.|\[::1\]|\[::ffff:127\.)' || true)"
  echo "fixture: running pid=$pid ready=$ready base=$BASE non_loopback_peers=${egress:-none}"
}

case "${1:-}" in
  start) cmd_start ;;
  stop) cmd_stop ;;
  status) cmd_status ;;
  *) echo "usage: $0 start|stop|status" >&2; exit 2 ;;
esac
