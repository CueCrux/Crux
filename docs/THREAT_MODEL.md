# Threat Model

This document describes the trust boundaries, adversary model, and security assumptions
for the Crux Daemon.

## Trust Boundaries

```
                       +-----------+
   Untrusted           |  Client   |      HTTP / gRPC
   (external)          +-----------+
                             |
   ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ | ─ ─ ─ ─ ─ ─ ─ TLS termination boundary
                             |
   Trusted (internal)        v
                       +-----------+       +-------------+
                       | corecruxd |------>|  Data dir   |
                       |  (daemon) |       | (segments)  |
                       +-----------+       +-------------+
                             |
                             v
                       +-----------+
                       | CROWN     |
                       | receipts  |
                       +-----------+
```

### Boundary 1: Client to Daemon

- **Network:** The daemon binds to `127.0.0.1` by default. Non-loopback binding with
  `DevScopes` or `Off` auth modes is blocked unless `CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND=1`
  is explicitly set.
- **TLS:** The Crux Daemon does **not** implement TLS natively. Deployments exposed
  beyond localhost **must** use a TLS-terminating reverse proxy (Caddy, nginx, Envoy).
- **Auth:** Controlled by `CORECRUXD_AUTH_MODE` (required, no default):
  - `off` - No authentication. All scope checks bypassed. Use only for local development.
  - `dev_scopes` - Scopes provided by client via HTTP headers. No cryptographic verification.
    Emits a startup warning. Suitable for development and testing only.
  - `jwt_hs256` - HS256 JWT verification with `exp`, `nbf` validation and 30s leeway.
  - `jwt_jwks` - JWKS/OIDC JWT verification. Production-recommended.

### Boundary 2: Daemon to Storage

- Segments are stored as files in `CORECRUXD_DATA_DIR`.
- BLAKE3 hashes ensure **integrity** (tamper detection), not **confidentiality**.
- Data at rest is **not encrypted**. Use filesystem-level encryption (LUKS, dm-crypt) if
  required by your threat model.

### Boundary 3: CROWN Receipts

- Ed25519 signatures provide non-repudiation and tamper evidence for appended events.
- The signing key is loaded from `CORECRUXD_RECEIPTS_KEYRING_PATH` or
  `CORECRUXD_RECEIPTS_KEYRING_JSON`.
- Key material is held in process memory. Compromise of the daemon process exposes the key.
- Store verification is performed by `corecruxctl verify-store`; CROWN receipt signature
  verification is performed by the receipt verifier and the `/v1/receipts/` API endpoints.

## Adversary Model

### What CROWN receipts protect against

- **Post-write tampering:** Any modification to sealed segments invalidates the BLAKE3 chain
  and Ed25519 signatures.
- **Selective omission:** The chain structure makes it computationally infeasible to remove
  events from sealed segments without detection.
- **Receipt forgery:** Without the Ed25519 private key, an adversary cannot produce valid
  receipts for fabricated events.

### What CROWN receipts do NOT protect against

- **Key compromise:** If the signing key is exfiltrated, all future receipts can be forged.
  Rotate keys and audit access to keyring files.
- **Pre-seal tampering:** Events in the active (unsealed) head segment are not yet covered
  by the sealed chain. The window is bounded by the seal interval.
- **Side-channel attacks:** The daemon does not implement constant-time signing; timing
  attacks on the Ed25519 operations are not mitigated.

## Auth Mode Implications

| Mode | Verification | Production-safe | Use case |
|------|-------------|-----------------|----------|
| `off` | None | No | Local development, air-gapped |
| `dev_scopes` | None (header pass-through) | No | Integration testing |
| `jwt_hs256` | Symmetric JWT (exp/nbf/iss/aud) | Qualified | Small deployments with shared secret |
| `jwt_jwks` | Asymmetric JWT via JWKS/OIDC | Yes | Production with identity provider |

## Network Assumptions

1. The daemon assumes the network between reverse proxy and daemon is trusted
   (loopback or private network). It only consumes `Forwarded` /
   `X-Forwarded-For` for rate-limit keying from peers listed in
   `CORECRUXD_TRUSTED_PROXY_CIDRS`.
2. gRPC replication between nodes should use authenticated channels
   (`CORECRUXD_REPLICATION_AUTH_BEARER`).
3. Prometheus metrics (`/metrics`) and health endpoints (`/healthz`, `/readyz`) are
   unauthenticated. Restrict access at the network level if exposing beyond localhost.
4. MCP Streamable HTTP server-info discovery can remain public, but SSE stream
   creation requires configured bearer auth when agent tokens are present.
5. Public `/v1/version` is redacted. Full operational version details live at
   `/v1/admin/version` behind `admin:read`.

## Error Response Policy

Error responses for shard routing errors (`SHARD_UNAVAILABLE`, `WRONG_SHARD`,
`SHARDMAP_VERSION_MISMATCH`) are sanitised by default and do not include internal topology
details (gRPC addresses, shard map versions). Set `CORECRUXD_DEBUG_ERRORS=true`
to include full details for debugging.

## Rate Limiting

The Crux Daemon implements coarse client-IP rate limiting and request caps.
Use your reverse proxy (Caddy `rate_limit`, nginx `limit_req`, etc.) for
route-specific resource protection. `X-Corecrux-Passport-Id` is not trusted as
a pre-auth rate-limit key; unauthenticated callers cannot rotate it to obtain
independent buckets.

Global request bodies default to 16 MiB. Bulk/import endpoints that need a
larger envelope have explicit route-specific limits. The console embedding
probe is an authenticated admin write operation and rejects metadata,
link-local, private, multicast, unspecified, and DNS-rebound targets by default
unless the target matches the configured embedding endpoint or an explicit
local-probe override is set.

## Route Authorization Proof

The CI test gate `route_auth_matrix_is_complete` parses the live Axum router
source and fails when a route lacks one of these classes: public, read, write,
admin read, admin write, internal replication, or feature-gated. Companion
tests pin representative scope contracts and high-risk HTTP boundary routes.

## Dependency Security

- `cargo deny check` is run in CI to detect known advisories, bans, licence
  drift, and source-policy violations.
- `cargo audit` is run in CI as a secondary RustSec advisory check. It
  currently surfaces the yanked `aes 0.9.0` warning through `zip 8.6.0`; this
  is visible but non-blocking until the upstream dependency path can move.
- Known RustSec ignores in `deny.toml` must carry owner and expiry comments; CI
  enforces this metadata.
- Container images are scanned with Trivy before push. Emergency skips require
  a structured waiver with owner, expiry, reason, commit SHA, run ID, and image
  reference, uploaded as a 90-day artifact.
- Parser/verifier fuzz targets run on the scheduled workflow and as bounded PR
  runs when fuzz, frame, receipt, router, or lockfile paths change. Crash and
  corpus artifacts are uploaded for follow-up.
