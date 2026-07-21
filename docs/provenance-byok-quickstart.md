# BYOK provenance API quickstart

The default-off provenance API signs an asset with a caller-supplied P-256
key, verifies the resulting sidecar envelope, and can retain a
passport-signed verification record. In the BYOK beta, Crux receives the key
for one request and does not retain, log, or echo it.

This is a local beta workflow. Metering is still a no-op, the feature flag is
off by default, and enabling or publishing the hosted surface remains an
operator gate.

## Prerequisites

- a local source build of `corecruxd`;
- `curl`, `jq`, and OpenSSL;
- ports `14800` and `14801` available.

The script uses `dev_scopes`, which is suitable only on a loopback listener.
Hosted deployments must use JWT auth behind authenticated TLS termination.

## 1. Start a disposable local daemon

From the repository root, use a fresh data directory:

```bash
export CORECRUXD_DATA_DIR="$(mktemp -d)"
export CORECRUXD_AUTH_MODE=dev_scopes
export CORECRUXD_FEATURE_PROVENANCE_API=1
cargo run --release --bin corecruxd
```

Wait for readiness from another terminal:

```bash
curl -fsS http://127.0.0.1:14800/readyz
```

Do not reuse `dev_scopes` on a non-loopback listener. The provenance routes
will not mount with auth off, or on a non-loopback listener unless JWT auth and
`CORECRUXD_PROVENANCE_TLS_TERMINATED=1` are both present.

## 2. Run the round-trip

```bash
./examples/provenance-byok/quickstart.sh
```

The script creates a disposable self-signed P-256 certificate, signs
[`asset.txt`](../examples/provenance-byok/asset.txt), verifies its asset
binding, creates a retained verification record, and repeats that request with
the same `Idempotency-Key`. The replay must return HTTP 200 and the original
record id rather than appending a second record.

It writes four non-secret response artifacts to
`./provenance-byok-output/`:

- `sign-response.json` — the sidecar envelope and asset hash;
- `verify-response.json` — integrity, asset-binding, and trust posture;
- `verify-record-response.json` — the retained record and receipt;
- `verify-record-replay.json` — the idempotent replay result.

The private key, certificate, and request bodies live only in a
permission-controlled temporary directory and are removed on exit. The script
never prints the key.

### Optional local P95 baseline

Run up to 30 create-path samples per operation without exceeding the local
per-credential window used by the quickstart:

```bash
CORECRUXD_BUILD_PROFILE=release \
PROVENANCE_BENCH_ITERATIONS=30 \
  ./examples/provenance-byok/quickstart.sh
```

This adds `benchmark.json`, with min/P50/P95/max latency for sign, stateless
verify, and new retained-record creation. The record includes the corpus
(`provenance-byok-sample-v1`), source commit, build profile, lane flags, and a
unique run id. It is a loopback baseline, not the hosted-beta P95 required by
the M9 launch gate.

The first reproducible release-profile run is retained at
[`docs/bench/provenance-byok-local-2026-07-21.json`](bench/provenance-byok-local-2026-07-21.json).

## Reading the verification result

For the disposable self-signed sample, `ok` is true while
`identity_trusted` and `chain_validated` are false. Those fields answer
different questions:

- `ok` means the canonical envelope signature and supplied asset binding both
  verify;
- `identity_trusted` means the exact, currently-valid leaf certificate is in
  the operator's `CORECRUXD_PROVENANCE_TRUSTED_LEAF_SHA256` list;
- `chain_validated` remains false in this beta because CA-chain/root
  validation is not implemented.

An exact leaf pin is a narrow operator policy, not a claim that a public CA
validated the signer. Malformed pin configuration fails closed and leaves the
routes unmounted.

## Abuse-control layers

The three provenance operations share one tenant-scoped budget of 120 calls
per minute for each verified stable JWT `sub` or `passport_id`. Refreshing a
token or switching from `verify` to `sign` does not reset that allowance.
Hosted JWTs without either stable identity claim fail closed; loopback-only
`dev_scopes` retains a hashed development-credential fallback. A rejected call
returns `429` and `Retry-After: 60`.

This principal budget complements the daemon-wide effective-client-IP token
bucket, request-body caps, and global in-flight/load-shed guard. A reverse
proxy's forwarded address is trusted only when its peer CIDR is explicitly in
`CORECRUXD_TRUSTED_PROXY_CIDRS`; loopback is otherwise exempt by default. Both
rate tables are process-local, so a horizontally scaled hosted deployment must
also enforce a shared edge/gateway limit and verify it during the external beta
drill.

## Optional retained-record lifecycle

Automatic deletion is off unless the operator selects a window before daemon
startup:

```bash
export CORECRUXD_PROVENANCE_RETENTION_DAYS=90
```

The accepted range is 1–3,650 days; zero, malformed, and out-of-range values
fail closed and keep the provenance routes unmounted. An authenticated
`verify-record` call can sweep that tenant before retaining the new result.
Full scans are limited to once per tenant per hour and the cadence table is
bounded; saturation preserves records instead of opening an unbounded memory
or I/O path. The sweep validates every segment before its first mutation, runs
under the same process and cross-process locks as appends, and atomically
replaces partially retained files. Every record whose timestamp can drive a
deletion must also pass its daemon-passport signature and body-hash check;
unknown signers or tampered timestamps preserve the tenant and fail closed.
After an intentional daemon passport rotation, provide a bounded
`CORECRUXD_PROVENANCE_RECORD_SIGNER_KEYRING_JSON` object mapping each retained
historical `p_…` fingerprint to its Ed25519 public-key hex. The fingerprint is
re-derived from every configured key; malformed, mismatched, or unknown keys
never authorize deletion.

Active legal holds are checked while the legal-hold read lock is held through
the sweep. A tenant-wide hold preserves every verification record. A scoped
hold can target `provenance::verification_record::<record_id>` (or the broader
`provenance::verification_record::` prefix). Malformed newest hold state is
resolved by the legal-hold store's tenant-wide fail-closed fallback.

Every deletion-producing sweep first durably mints a count-only `planned` governance
receipt under `__governance__::retention`; deletion does not begin if that
intent cannot be recorded. A second `completed` or `failed` receipt uses the
same sweep id after the attempt, including failures before the first file
mutation. These contain the tenant hash and counts, never
raw tenant ids, record ids, asset bytes, or caller text. The triggering
response reports the final receipt:

- `X-Cuecrux-Retention-Receipt-Status: recorded|pending`;
- `X-Cuecrux-Retention-Receipt-Id` when minting succeeds;
- `X-Cuecrux-Retention-Records-Dropped`.

`pending` is loud audit debt: the deletion is not rolled back, and the daemon
increments/logs its governance-receipt failure signal.

Inactive-tenant scheduling is a separate, default-off operator choice:

```bash
export CORECRUXD_PROVENANCE_RETENTION_SCHEDULER=true
export CORECRUXD_PROVENANCE_RETENTION_INTERVAL_SECS=3600
export CORECRUXD_PROVENANCE_RETENTION_MAX_TENANTS_PER_PASS=100
```

It requires the retention-days policy above, skips the immediate boot tick,
discovers only exact hash-bound tenant directories, and rotates through a
bounded batch (interval 60–86,400 seconds; batch 1–1,000). Explicit malformed
or out-of-range scheduler bounds disable the task rather than being clamped.
Each pass starts its 30-second deadline before discovery, checks it and
shutdown during discovery, lock acquisition, and record validation, and
conservatively debits discovered store bytes from the 512-MiB cap before
rechecking the remaining budget under each tenant lock. Malformed no-newline
records are cut off at the line bound rather than scanned to EOF. A budget-hit directory advances the
round-robin cursor so it cannot starve later tenants. Once a
durable `planned` receipt exists, that tenant's bounded atomic mutation and
terminal receipt finish before shutdown; while waiting to mint that intent,
shutdown/deadline cancellation is still observed. Later tenants are skipped. The
scheduler shares the request-path hourly tenant cadence. Scheduled receipts use the fixed actor
`provenance-retention-scheduler` and trigger `scheduled`; they contain the same
counts and hashed tenant identity as request-triggered receipts.

Automatic verification-record deletion (request-triggered or scheduled) is
currently enabled only on Linux, where every existing directory component is
opened descriptor-relative with no symlink traversal and mutations remain
anchored to the opened tenant directory. Other platforms preserve records and
fail the configured deletion attempt closed. The scheduler is
independent of `CORECRUXD_FEATURE_PROVENANCE_API`: routes may stay off while a
separately approved lifecycle task runs. A hosted activation and deletion
drill remain operator gates.

## API shape

All three routes require `provenance:write` or `admin:write`, plus an explicit
tenant authorized by the caller's credential:

| Method | Route | Success |
|---|---|---|
| `POST` | `/v1/provenance/sign` | `201` |
| `POST` | `/v1/provenance/verify` | `200` |
| `POST` | `/v1/provenance/verify-record` | `201`, or `200` for an exact idempotent replay |

The daemon-wide ingress layer supplies trusted-proxy-aware client-IP limiting;
the provenance handlers add a bounded per-credential limiter. Configure
`CORECRUXD_TRUSTED_PROXY_CIDRS` only for proxies that strip inbound
`Forwarded` and `X-Forwarded-For` before setting the real client address.

## Stop and clean up

Stop the foreground daemon with `Ctrl-C`. The data directory named by
`CORECRUXD_DATA_DIR` contains the retained sample record; delete that
disposable directory only after checking the path.
