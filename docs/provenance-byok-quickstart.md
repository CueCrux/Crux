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
