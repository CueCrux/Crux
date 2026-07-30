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
4. MCP Streamable HTTP requests fail closed whenever either registered bearer
   tokens or hosted-client OAuth introspection is configured. This includes
   server-info GET, SSE stream creation, and JSON-RPC POST; only an MCP daemon
   with neither authentication rail configured permits anonymous access.
5. Public `/v1/version` is redacted. Full operational version details live at
   `/v1/admin/version` behind `admin:read`.

## Capability Token Trust and Revocation

- **Local-token trust invariant.** The capability router (`crux-router`) skips
  signature verification for the `local` backend. This is sound only because the
  token reaching the router is daemon-minted (self-minted local token in
  `corecruxd` startup) and never client-injected — the local token does not
  cross a trust boundary. Hosted/customer backends are always signature-verified
  against a configured trusted issuer key; the local short-circuit cannot be
  leveraged to authorise a hosted lane. A future change that routes a
  client-supplied token through the router must construct it with a trusted
  issuer pubkey. This is pinned by the
  `local_signature_bypass_does_not_extend_to_hosted_backend` regression test.
- **Revocation is modelled but not yet enforced.** Tokens carry `crl_url` and
  `push_channel` revocation hints, but the router does not yet consult them, so a
  revoked-but-unexpired token is still authorised within its validity window.
  To avoid misleading downstream auditors, the router mode stamp carries
  `revocation_checked: false`; an authorised decision does **not** imply the
  token was checked against a CRL or revocation timestamp. Mitigation today:
  keep token lifetimes short. Revocation IO (CRL/timestamp consult) is a planned
  later phase.

## Key Escrow and Recovery

Scope: the `crux-escrow` crate. A vault's data encryption key (DEK) never leaves the
customer's control in plaintext. This section is the M0 artefact of the key escrow and
recovery plan and is the contract the crate's tests assert against.

### Recovery modes

| Mode | What the server holds | Reconstructs the DEK | Customer artefacts |
|---|---|---|---|
| **Layer 0 — recovery code** (default) | wrapped DEK ciphertext only | the recovery code alone | one 256-bit code, shown once |
| **Layer 1 — Shamir 2-of-3** (opt-in) | wrapped DEK ciphertext + **share C** | any **two** of A/B/C | device share A, printed share B |

Layer 0 is not escrow: we hold ciphertext and no key-derivation input. Layer 1 adds one
share, deliberately one short of a threshold.

### Adversaries

| Adversary | Capability assumed | Defeated by | Residual |
|---|---|---|---|
| **Us (honest)** | full read of every server-side store | share C is 1 of 3 in a 2-of-3 scheme; Layer 0 stores no key input at all | none — insufficiency is arithmetic, not policy |
| **A breached us** | offline copy of everything at rest, including share C | same threshold argument; share C is stored non-exportable and its release is an operation, not a read | an attacker who *also* phishes share A or B reconstructs. Two independent compromises required |
| **An account thief** (valid passport, no device) | authenticated as the account holder | release of share C is delayed (default 72h), notified to every registered device, and cancellable by any of them | a thief who holds the account **and** all registered devices **and** waits out the window succeeds. This is the account-recovery floor for any online system |
| **A network observer** | full transcript of client↔server traffic | only wrapped ciphertext and share-C *release decisions* cross the wire; unwrapping is client-side | traffic analysis reveals *that* a recovery occurred, not the key. Metadata is receipted anyway |
| **A coerced operator** (court order, insider under duress) | can compel production of everything we hold | share C alone reconstructs nothing; there is no server-holds-the-key mode to compel | we can be compelled to hand over a useless share, and to say so. Published in the M5 transparency statement |
| **A malicious client** | crafted shares, replayed or forged release requests | shares are integrity-tagged (corruption is detected, not silently mis-reconstructed); release requests are passport-bound and receipted | a client that already holds 2 valid shares is the legitimate owner by construction |

### Constraint mapping

Each constraint from the plan maps to a named defence, or is an accepted risk:

1. **Boring** — CSPRNG (`rand`), BLAKE3 in KDF mode (`derive_key`) to turn the recovery
   code into a wrapping key, XChaCha20-Poly1305 AEAD to wrap the DEK, and a published
   Shamir implementation over GF(2^8). All four are existing workspace dependencies or a
   vetted addition; no novel construction.

   A password KDF (Argon2id, scrypt) is deliberately **not** used. The recovery code is 256
   bits of CSPRNG output, not a user-chosen password: there is no low-entropy input for a
   memory-hard function to defend, and it would only add a dependency and a tuning
   parameter. This is the same reasoning recorded for the relay device-credential secret.
2. **Insufficient by construction** — enforced by the threshold, and asserted by the
   `one_share_yields_nothing` and `server_dump_yields_nothing` tests. Neither test can
   pass if the server's holdings ever become sufficient.
3. **Redundant without weakening** — share C may be replicated freely (Vault + sealed
   offline backup) *because* it is insufficient alone. Replication count does not appear
   in any security argument, so operational care is not load-bearing.
4. **Receipted** — every wrap, escrow opt-in, release request, notification, cancellation
   and completion emits a CROWN receipt into the customer's own timeline.

### Unrecoverable by design

**Losing both user shares (A and B, or the Layer 0 recovery code) is unrecoverable.**
This is not a gap to close later. The only way to make it recoverable is for our holdings
alone to reconstruct the DEK — which is Constraint 2 inverted, and would mean a breach of
us is a breach of every customer's data. We accept permanent loss in the rare case in
order to make catastrophic loss impossible in the common one.

Product consequence: the customer must be told this *before* opting in, in the UI, not in
a help article afterwards. That is the M6 launch gate.

### Not defended against

- **A compromised client device at wrap time.** If the endpoint that generates the DEK is
  owned, escrow is irrelevant — the plaintext is already there.
- **A user who photographs their recovery code into cloud storage.** Out of scope; the
  code is rendered for transcription, with print/download offered once.
- **Rubber-hose against the *customer*.** They hold 2-of-3 by design; they can be compelled
  to use it. No key-holder scheme defends against this.

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
- `cargo deny`'s `wildcards` policy is `deny`: no workspace crate may declare a
  `"*"` version. `multiple-versions` remains `warn` because two RustCrypto
  generations coexist (the stable `digest 0.10` / `der 0.7` stack from
  `ed25519-dalek` and `p256`/`ecdsa`, and the `digest 0.11` / `der 0.8` stack
  from `cms`, `x509-cert`, and `zip`). This duplication is tracked, not silently
  accepted; the crypto subset will move to a targeted `deny` once upstreams
  converge.
- **Pre-release crypto in witness verification.** `corecrux-receipts` depends on
  `cms 0.3.0-pre.2` and `x509-cert 0.3.0-rc.4`. These parse RFC3161 timestamp
  tokens for the optional witness/co-signature path only — they are not in the
  core CROWN Ed25519 receipt signing/verification path, which uses stable
  `ed25519-dalek 2.x`. `cms` is the only Rust CMS/PKCS#7 parser and is still
  pre-release upstream, so it cannot be replaced with a stable equivalent today.
  Treat witness-timestamp parsing as a defence-in-depth signal, not a primary
  trust anchor, until these crates reach a stable release.
