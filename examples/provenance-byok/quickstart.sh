#!/usr/bin/env bash
# Local BYOK provenance round-trip. The generated private key stays in a
# disposable directory and is removed on exit; response artifacts contain no
# asset bytes or private-key material.

set -euo pipefail

for required_command in curl jq openssl; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    echo "ERROR: $required_command is required" >&2
    exit 1
  fi
done

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
asset_path="$script_dir/asset.txt"
base_url=${CORECRUXD_HTTP_URL:-http://127.0.0.1:14800}
tenant_id=${CORECRUXD_PROVENANCE_TENANT:-quickstart}
output_dir=${1:-"$PWD/provenance-byok-output"}
benchmark_iterations=${PROVENANCE_BENCH_ITERATIONS:-0}

if [[ ! "$benchmark_iterations" =~ ^(0|[1-9]|[12][0-9]|30)$ ]]; then
  echo "ERROR: PROVENANCE_BENCH_ITERATIONS must be an integer from 0 to 30" >&2
  exit 1
fi

secret_dir=$(mktemp -d "${TMPDIR:-/tmp}/cuecrux-provenance-byok.XXXXXXXX")

cleanup() {
  if [[ -n "${secret_dir:-}" && -d "$secret_dir" && "$secret_dir" == *cuecrux-provenance-byok.* ]]; then
    rm -f -- \
      "$secret_dir/key.pem" \
      "$secret_dir/cert.pem" \
      "$secret_dir/sign-request.json" \
      "$secret_dir/verify-request.json" \
      "$secret_dir/sign-latency-seconds.txt" \
      "$secret_dir/sign-latency-seconds.txt.sorted" \
      "$secret_dir/verify-latency-seconds.txt" \
      "$secret_dir/verify-latency-seconds.txt.sorted" \
      "$secret_dir/verify-record-latency-seconds.txt" \
      "$secret_dir/verify-record-latency-seconds.txt.sorted" \
      "$secret_dir/bench-sign-response.json" \
      "$secret_dir/bench-verify-response.json" \
      "$secret_dir/bench-record-response.json"
    rmdir -- "$secret_dir"
  fi
}
trap cleanup EXIT

mkdir -p -- "$output_dir"

openssl genpkey \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 \
  -out "$secret_dir/key.pem" 2>/dev/null
openssl req \
  -new \
  -x509 \
  -sha256 \
  -key "$secret_dir/key.pem" \
  -out "$secret_dir/cert.pem" \
  -days 1 \
  -subj '/CN=cuecrux-byok-quickstart.invalid' 2>/dev/null

content_b64=$(openssl base64 -A -in "$asset_path")
signing_key_pem=$(<"$secret_dir/key.pem")
cert_chain_pem=$(<"$secret_dir/cert.pem")

jq -n \
  --arg content_b64 "$content_b64" \
  --arg signing_key_pem "$signing_key_pem" \
  --arg cert_chain_pem "$cert_chain_pem" \
  --arg tenant_id "$tenant_id" \
  '{
    content_b64: $content_b64,
    content_type: "text/plain",
    signing_key_pem: $signing_key_pem,
    cert_chain_pem: $cert_chain_pem,
    tenant_id: $tenant_id,
    key_id: "quickstart-disposable",
    manifest: {claim_generator: "cuecrux/provenance-byok-quickstart"}
  }' >"$secret_dir/sign-request.json"

curl -sS --fail-with-body \
  -X POST "$base_url/v1/provenance/sign" \
  -H 'Content-Type: application/json' \
  -H 'X-Corecrux-Scopes: provenance:write' \
  -H "X-Corecrux-Tenant-Id: $tenant_id" \
  --data-binary "@$secret_dir/sign-request.json" \
  >"$output_dir/sign-response.json"

jq -e '
  .signature_alg == "es256" and
  (.manifest_envelope_b64 | type == "string" and length > 0) and
  (.content_hash_blake3_hex | type == "string" and length == 64)
' "$output_dir/sign-response.json" >/dev/null

envelope_b64=$(jq -er '.manifest_envelope_b64' "$output_dir/sign-response.json")
jq -n \
  --arg manifest_envelope_b64 "$envelope_b64" \
  --arg content_b64 "$content_b64" \
  --arg tenant_id "$tenant_id" \
  '{
    manifest_envelope_b64: $manifest_envelope_b64,
    content_b64: $content_b64,
    tenant_id: $tenant_id
  }' >"$secret_dir/verify-request.json"

curl -sS --fail-with-body \
  -X POST "$base_url/v1/provenance/verify" \
  -H 'Content-Type: application/json' \
  -H 'X-Corecrux-Scopes: provenance:write' \
  -H "X-Corecrux-Tenant-Id: $tenant_id" \
  --data-binary "@$secret_dir/verify-request.json" \
  >"$output_dir/verify-response.json"

jq -e '
  .ok == true and
  .integrity_valid == true and
  .asset_binding_checked == true and
  .content_hash_match == true and
  .identity_trusted == false and
  .chain_validated == false and
  .trust_status == "untrusted_presented_leaf" and
  (.signer_leaf_sha256 | type == "string" and length == 64)
' "$output_dir/verify-response.json" >/dev/null

idempotency_key="quickstart-$(openssl rand -hex 12)"
record_status=$(curl -sS \
  -o "$output_dir/verify-record-response.json" \
  -w '%{http_code}' \
  -X POST "$base_url/v1/provenance/verify-record" \
  -H 'Content-Type: application/json' \
  -H 'X-Corecrux-Scopes: provenance:write' \
  -H "X-Corecrux-Tenant-Id: $tenant_id" \
  -H "Idempotency-Key: $idempotency_key" \
  --data-binary "@$secret_dir/verify-request.json")
[[ "$record_status" == 201 ]]

replay_status=$(curl -sS \
  -o "$output_dir/verify-record-replay.json" \
  -w '%{http_code}' \
  -X POST "$base_url/v1/provenance/verify-record" \
  -H 'Content-Type: application/json' \
  -H 'X-Corecrux-Scopes: provenance:write' \
  -H "X-Corecrux-Tenant-Id: $tenant_id" \
  -H "Idempotency-Key: $idempotency_key" \
  --data-binary "@$secret_dir/verify-request.json")
[[ "$replay_status" == 200 ]]

record_id=$(jq -er '.record_id' "$output_dir/verify-record-response.json")
replay_record_id=$(jq -er '.record_id' "$output_dir/verify-record-replay.json")
[[ "$record_id" == "$replay_record_id" ]]
jq -e '.verification.ok == true and (.receipt.signature | length > 0)' \
  "$output_dir/verify-record-response.json" >/dev/null

percentile_summary() {
  local series_path=$1
  local sample_count=$2
  local sorted_path="$series_path.sorted"
  local p50_index=$(((50 * sample_count + 99) / 100))
  local p95_index=$(((95 * sample_count + 99) / 100))

  LC_ALL=C sort -n "$series_path" >"$sorted_path"
  printf '%s %s %s %s\n' \
    "$(head -n 1 "$sorted_path")" \
    "$(sed -n "${p50_index}p" "$sorted_path")" \
    "$(sed -n "${p95_index}p" "$sorted_path")" \
    "$(tail -n 1 "$sorted_path")"
}

if ((benchmark_iterations > 0)); then
  run_id="provenance-byok-local-$(date -u +%Y%m%dT%H%M%SZ)-$(openssl rand -hex 4)"
  : >"$secret_dir/sign-latency-seconds.txt"
  : >"$secret_dir/verify-latency-seconds.txt"
  : >"$secret_dir/verify-record-latency-seconds.txt"

  for iteration in $(seq 1 "$benchmark_iterations"); do
    curl -sS --fail-with-body \
      -o "$secret_dir/bench-sign-response.json" \
      -w '%{time_total}\n' \
      -X POST "$base_url/v1/provenance/sign" \
      -H 'Content-Type: application/json' \
      -H 'X-Corecrux-Scopes: provenance:write' \
      -H "X-Corecrux-Tenant-Id: $tenant_id" \
      --data-binary "@$secret_dir/sign-request.json" \
      >>"$secret_dir/sign-latency-seconds.txt"

    curl -sS --fail-with-body \
      -o "$secret_dir/bench-verify-response.json" \
      -w '%{time_total}\n' \
      -X POST "$base_url/v1/provenance/verify" \
      -H 'Content-Type: application/json' \
      -H 'X-Corecrux-Scopes: provenance:write' \
      -H "X-Corecrux-Tenant-Id: $tenant_id" \
      --data-binary "@$secret_dir/verify-request.json" \
      >>"$secret_dir/verify-latency-seconds.txt"

    curl -sS --fail-with-body \
      -o "$secret_dir/bench-record-response.json" \
      -w '%{time_total}\n' \
      -X POST "$base_url/v1/provenance/verify-record" \
      -H 'Content-Type: application/json' \
      -H 'X-Corecrux-Scopes: provenance:write' \
      -H "X-Corecrux-Tenant-Id: $tenant_id" \
      -H "Idempotency-Key: bench-${run_id}-${iteration}" \
      --data-binary "@$secret_dir/verify-request.json" \
      >>"$secret_dir/verify-record-latency-seconds.txt"
  done

  read -r sign_min sign_p50 sign_p95 sign_max < <(
    percentile_summary "$secret_dir/sign-latency-seconds.txt" "$benchmark_iterations"
  )
  read -r verify_min verify_p50 verify_p95 verify_max < <(
    percentile_summary "$secret_dir/verify-latency-seconds.txt" "$benchmark_iterations"
  )
  read -r record_min record_p50 record_p95 record_max < <(
    percentile_summary "$secret_dir/verify-record-latency-seconds.txt" "$benchmark_iterations"
  )

  source_commit=$(git -C "$script_dir/../.." rev-parse HEAD 2>/dev/null || printf unknown)
  jq -n \
    --arg schema "cuecrux.provenance_latency.v1" \
    --arg run_id "$run_id" \
    --arg corpus "provenance-byok-sample-v1" \
    --arg commit_sha "$source_commit" \
    --arg build_profile "${CORECRUXD_BUILD_PROFILE:-unknown}" \
    --argjson iterations "$benchmark_iterations" \
    --arg sign_min "$sign_min" --arg sign_p50 "$sign_p50" --arg sign_p95 "$sign_p95" --arg sign_max "$sign_max" \
    --arg verify_min "$verify_min" --arg verify_p50 "$verify_p50" --arg verify_p95 "$verify_p95" --arg verify_max "$verify_max" \
    --arg record_min "$record_min" --arg record_p50 "$record_p50" --arg record_p95 "$record_p95" --arg record_max "$record_max" \
    '{
      schema: $schema,
      run_id: $run_id,
      corpus: $corpus,
      commit_sha: $commit_sha,
      build_profile: $build_profile,
      lane_flags: {
        provenance_api: true,
        auth_mode: "dev_scopes",
        meter: "noop",
        trust_policy: "untrusted_presented_leaf",
        transport: "loopback_http"
      },
      iterations_per_operation: $iterations,
      unit: "seconds",
      latency: {
        sign: {min: ($sign_min | tonumber), p50: ($sign_p50 | tonumber), p95: ($sign_p95 | tonumber), max: ($sign_max | tonumber)},
        verify: {min: ($verify_min | tonumber), p50: ($verify_p50 | tonumber), p95: ($verify_p95 | tonumber), max: ($verify_max | tonumber)},
        verify_record_create: {min: ($record_min | tonumber), p50: ($record_p50 | tonumber), p95: ($record_p95 | tonumber), max: ($record_max | tonumber)}
      },
      scope: "local baseline only; not a hosted-beta SLO"
    }' >"$output_dir/benchmark.json"
fi

leaf_fingerprint=$(openssl x509 -in "$secret_dir/cert.pem" -outform DER \
  | openssl dgst -sha256 -hex \
  | awk '{print $NF}')

printf 'BYOK provenance quickstart passed.\n'
printf 'Artifacts: %s\n' "$output_dir"
printf 'Record: %s (replay returned the same record)\n' "$record_id"
printf 'Disposable leaf SHA-256: %s\n' "$leaf_fingerprint"
printf 'Trust stayed false, as expected: an exact leaf pin is an operator policy, not a chain claim.\n'
if ((benchmark_iterations > 0)); then
  printf 'Local P95 baseline: %s\n' "$output_dir/benchmark.json"
fi
