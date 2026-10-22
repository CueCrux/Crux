#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# End-to-end Jev decision receipt against the fixture daemon
# (fixture-daemon.sh start first). No Jev call is made: the "decision" is a
# canned example, only its hashes go to Crux.
#
#   a. principal: fixture registered passport "jev-agent" and minted its token
#   b. POST /v1/mediation/receipts  model_invocation draft -> signed receipt
#   c. GET  /v1/receipts/{id}[/signature|/verification]
#   d. offline: Ed25519 over the CBOR body with the daemon public key
#      (openssl), blake3 bindings (b3sum, if installed), corecruxctl COSE
#   e. PUT  /v1/facts  decision fact with source_receipt = receipt id
#   f. negative control: one flipped body byte must fail verification
#
# Env: JEV_FIXTURE_DIR (same as fixture-daemon.sh), CORECRUXCTL (default:
# corecruxctl on PATH). Artefacts land in $JEV_FIXTURE_DIR/recipe/.
set -euo pipefail

FIX="${JEV_FIXTURE_DIR:-${TMPDIR:-/tmp}/jev-crux-fixture}"
CTL="${CORECRUXCTL:-$(command -v corecruxctl || true)}"
# shellcheck disable=SC1091
. "$FIX/fixture.env"
B="$CRUX_BASE_URL"
OUT="$FIX/recipe"
rm -rf "$OUT"; mkdir -p "$OUT"; cd "$OUT"
# Token goes to curl via a 0600 header file, never argv or stdout.
(umask 077; printf 'Authorization: Bearer %s\n' "$(cat "$CRUX_TOKEN_FILE")" > auth.h)

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*" >&2; exit 1; }
sha() { printf 'sha256:%s' "$(sha256sum "$1" | cut -d' ' -f1)"; }
api() { # api METHOD PATH [curl args...] -> body in $OUT/resp.json, echoes status
  local m="$1" p="$2"; shift 2
  curl -s -o resp.json -w '%{http_code}' -X "$m" "$B$p" -H @auth.h "$@"
}

# ── the Jev call being recorded ────────────────────────────────────────────
# Demo digests only: sha256 over these exact file bytes, trailing newline
# included. Not the adapter's form (compact JSON of {state, questions}, key
# order preserved, not sorted); see the cookbook's "Canonical hashing".
cat > state.json <<'EOF'
{"options":["approve","escalate","reject"],"questions":["Should this invoice be paid?"],"state":{"amount_eur":1840.5,"invoice_id":"INV-4711","vendor":"acme-gmbh"}}
EOF
cat > output.json <<'EOF'
{"answer":"approve","probabilities":{"approve":0.93,"escalate":0.06,"reject":0.01}}
EOF
printf '%s' "crux-retrieval-set:fact_a,fact_b" > retrieval_set.txt
PROMPT_HASH="$(sha state.json)"
RSET_HASH="$(sha retrieval_set.txt)"
OUTPUT_HASH="$(sha output.json)"
INV="jev-inv-$(date +%s)-$$"

# ── b. mint ────────────────────────────────────────────────────────────────
jq -n --arg inv "$INV" --arg ph "$PROMPT_HASH" --arg rh "$RSET_HASH" --arg oh "$OUTPUT_HASH" '{
  kind: "model_invocation",
  invocation_id: $inv,
  session_id: "jev-decisions",
  provider: "typesafe",
  model_id: "jev-1.13",
  model_version: "jev-1.13",
  provider_request_id: "req_example_0001",
  prompt_hash: $ph,
  retrieval_set_hash: $rh,
  output_hash: $oh,
  started_at: "2026-09-22T12:00:00Z",
  completed_at: "2026-09-22T12:00:01Z"
}' > draft.json
code="$(api POST /v1/mediation/receipts -H 'content-type: application/json' --data @draft.json)"
[ "$code" = 201 ] || fail "b. mint HTTP $code $(cat resp.json)"
cp resp.json mint.json
RID="$(jq -r .receipt_id mint.json)"
BODY_HASH="$(jq -r .body_hash mint.json)"
KEY_ID="$(jq -r .signed_by mint.json)"
pass "b. minted $RID kind=$(jq -r .kind mint.json) body_hash=$BODY_HASH signed_by=$KEY_ID"

# ── c. daemon read-back ────────────────────────────────────────────────────
for sfx in "" /signature; do
  code="$(api GET "/v1/receipts/$RID$sfx?tenant_id=$CRUX_TENANT")"
  # Crux Daemon has no dataplane (corecruxd main.rs:611), so body/signature
  # by id are 501 for every receipt; stream receipts live in the mediation
  # observation log instead (receipts.rs:676-678).
  echo "INFO  c. GET /v1/receipts/{id}$sfx -> HTTP $code $(jq -r '.detail // empty' resp.json)"
done
code="$(api GET "/v1/receipts/$RID/verification?tenant_id=$CRUX_TENANT")"
cp resp.json verification.json
[ "$code" = 200 ] || fail "c. verification HTTP $code $(cat verification.json)"
jq -e --arg h "${BODY_HASH#blake3:}" '.signature_valid == true and .error_code == "OK"
  and .integrity.payload_hash_matches and .binding.tenant_bound and .binding.receipt_id_bound
  and .binding.chain_position_checked and .payload_hash == $h' verification.json >/dev/null \
  || fail "c. verification report: $(cat verification.json)"
pass "c. /verification signature_valid=true error_code=OK chain_position_checked=true"

code="$(api GET "/v1/observations/aggregate?kind=model_invocation&limit=500")"
[ "$code" = 200 ] || fail "c. observations HTTP $code"
jq --arg r "$RID" '[.observations[] | select(.payload.receipt_id == $r)]' resp.json > claims.json
# A minter may choose receipt_id and the daemon does not refuse a repeat, so
# one id can name two signed bodies. Exactly one distinct body, or stop.
n="$(jq '[.[].payload.body_cbor_hex] | unique | length' claims.json)"
[ "$n" != 0 ] || fail "c. receipt not in mediation log"
[ "$n" = 1 ] || fail "c. receipt id $RID claimed by $n distinct bodies"
jq '.[0]' claims.json > record.json
jq -r .payload.body_cbor_hex record.json | xxd -r -p > body.cbor
jq -r .payload.sig.signature_hex record.json | xxd -r -p > sig.bin
pass "c. body ($(wc -c < body.cbor) bytes CBOR) + ed25519 sig ($(wc -c < sig.bin) bytes) from /v1/observations/aggregate"

# ── d. offline verification ────────────────────────────────────────────────
verify_body() { openssl pkeyutl -verify -pubin -inkey "$CRUX_DAEMON_PUBKEY_PEM" -rawin -in "$1" -sigfile sig.bin; }
verify_body body.cbor >/dev/null || fail "d. openssl ed25519 verify"
pass "d. openssl ed25519 verify over body.cbor with daemon.pub.pem: Signature Verified Successfully"
for h in "$PROMPT_HASH" "$RSET_HASH" "$OUTPUT_HASH" "$INV" typesafe jev-1.13 req_example_0001 "$RID"; do
  grep -qaF "$h" body.cbor || fail "d. signed body is missing $h"
done
pass "d. signed body binds prompt/retrieval_set/output hashes, invocation_id, provider, model, request id"
if command -v b3sum >/dev/null; then
  [ "blake3:$(b3sum --no-names body.cbor)" = "$BODY_HASH" ] || fail "d. blake3(body) != body_hash"
  PK_FPR="$(openssl pkey -pubin -in "$CRUX_DAEMON_PUBKEY_PEM" -outform DER | tail -c 32 | b3sum --no-names)"
  [ "p_${PK_FPR:0:32}" = "$KEY_ID" ] || fail "d. pubkey does not match key_id $KEY_ID"
  [ "$PK_FPR" = "$(jq -r .pubkey_fingerprint verification.json)" ] || fail "d. pubkey fingerprint mismatch"
  pass "d. blake3(body)==body_hash; blake3(pubkey) matches key_id and daemon pubkey_fingerprint"
else
  echo "SKIP  d. b3sum not installed: blake3 body_hash / key_id binding not checked"
fi
if [ -x "$CTL" ]; then
  # corecruxctl has no generic `receipts verify` (ReceiptsCommand, corecruxctl
  # main.rs:2190), and export-cose only takes a CROWN *retrieval* receipt
  # (CrownReceiptV1: snap-id, answer-id, query-hash, ...). Probe it so this
  # line flips when model_invocation export lands.
  python3 -c 'import sys,json; print(json.dumps({"receipt": json.load(open("record.json"))["payload"]}))' > receipt.json
  if "$CTL" receipts export-cose receipt.json --out receipt.cose --gen-dev-key --kid dev:v1 > cose.log 2>&1; then
    "$CTL" receipts verify-cose receipt.cose || fail "d. verify-cose"
    pass "d. corecruxctl export-cose + verify-cose"
  else
    echo "GAP   d. corecruxctl export-cose rejects model_invocation receipts: $(tail -n1 cose.log)"
  fi
fi

# ── e. decision fact linked to the receipt ─────────────────────────────────
ENTITY="jev::invoice-INV-4711"
jq -n --arg e "$ENTITY" --arg r "$RID" --arg v "$(cat output.json)" \
  '{entity: $e, key: "decision:pay-invoice", value: $v, source_receipt: $r, confidence: 0.93}' > fact.json
code="$(api PUT /v1/facts -H 'content-type: application/json' --data @fact.json)"
[ "$code" = 201 ] || fail "e. PUT /v1/facts HTTP $code $(cat resp.json)"
FID="$(jq -r .fact_id resp.json)"
code="$(api GET "/v1/facts/$FID")"
[ "$code" = 200 ] && [ "$(jq -r .source_receipt resp.json)" = "$RID" ] || fail "e. read-back $code $(cat resp.json)"
code="$(api GET "/v1/facts/entity/$ENTITY")"
jq -e --arg r "$RID" '[.facts[] | select(.source_receipt == $r)] | length == 1' resp.json >/dev/null \
  || fail "e. entity listing $code $(cat resp.json)"
pass "e. fact $FID entity=$ENTITY source_receipt=$RID (by id and by entity)"

# ── f. negative control ────────────────────────────────────────────────────
off=$(( $(wc -c < body.cbor) / 2 ))
python3 -c 'import sys; b=bytearray(open("body.cbor","rb").read()); b[int(sys.argv[1])]^=1; open("tampered.cbor","wb").write(b)' "$off"
cmp -s body.cbor tampered.cbor && fail "f. tamper did not change the body"
if verify_body tampered.cbor >/dev/null 2>&1; then fail "f. tampered body still verifies"; fi
if command -v b3sum >/dev/null && [ "blake3:$(b3sum --no-names tampered.cbor)" = "$BODY_HASH" ]; then
  fail "f. tampered body still matches body_hash"
fi
pass "f. flipped 1 bit at byte $off: ed25519 verify FAILS and body_hash no longer matches"

echo "OK    receipt=$RID fact=$FID artefacts=$OUT"
