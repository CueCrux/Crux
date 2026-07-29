<!--
Copyright (c) 2026 CueCrux Ltd.
Licensed under the Apache License, Version 2.0.
-->

# M7a — Device pairing: protocol + threat model

ExecPlan `crux-desktop-mission-control-2026-07-19`, milestone **M7a**. Decide how
a daemon opts into pairing with an account so `app.cuecrux.com` can later reach
it (M8, carved out): reuse vs. supersede the existing device mechanisms, define
per-device proof-of-possession, and specify key custody + revocation. M7a is the
design gate; **M7b** (Engine registry schema/API) and **M7c** (staging
integration) are the implementation, which lands in the Engine repo + staging and
is operator-gated.

## Existing mechanisms (verified on origin/main) — reuse, do not reinvent

Two device-shaped mechanisms already exist; M7 must build on them, not add a
third:

1. **RFC 8628 device-authorization grant** — `crates/corecruxd/src/http/auth_device.rs`
   (`/v1/auth/device/start|token|refresh|revoke`, `/activate`). Default-off. The
   browser-login leg ("enter a code, approve on the console"). **Limitation:**
   pending grants + refresh credentials live **in memory** and are
   restart-invalidated; refresh does not rotate the secret. Good for the human
   authorization step; not a durable device identity.
2. **`passport_link_device`** — `crates/crux-mcp/src/tools/identity.rs`: binds a
   caller-supplied 64-hex device fingerprint to a passport (operator-tier).
   **Limitation:** the checked path only **format-validates** the fingerprint —
   it does **not** prove possession of any corresponding private key. A caller
   can claim any fingerprint.

**Decision:** *reuse* the RFC 8628 grant for the one-time human authorization
step; *supersede* `passport_link_device`'s format-only binding with a real
proof-of-possession (below). Neither is an Engine-account device registry — that
is net-new (M7b).

## The core property: passport attribution + per-device proof-of-possession

"Passport-derived device token" is the wrong shape — deriving a secret from
identity material yields a **cloneable deterministic bearer**. The property we
actually want is *passport attribution* **plus** *per-device proof of
possession*:

- Each device generates a **per-device asymmetric keypair** (Ed25519 — already
  the pervasive primitive: receipts, passports, agent-cards, capability-tokens).
  The **private key never leaves the device**; only the public key is registered.
- Pairing = the RFC 8628 human-approval step binds the device **public key** to
  the account/tenant in the Engine registry (M7b), attributed to the approving
  passport.
- Every subsequent privileged action carries a **signature over a fresh
  server-nonce** (challenge–response) — proving possession without sending the
  key. Reuses the anti-relay pattern already chosen for federation peers
  (OD-36: short-TTL server nonce + single-use replay cache), since the daemon
  sits behind a TLS-terminating ingress and cannot use TLS channel-binding.

A rotating opaque credential (random, server-stored hash, refresh-with-reuse-
detection) is the acceptable alternative where asymmetric PoP is impractical;
the non-negotiable is that a captured bearer alone must not grant durable access.

## Key custody across Windows / WSL / service contexts

The daemon is intended to keep running after the desktop app exits (attach mode,
M1/M5a). Therefore the device credential **must be daemon-held**, not only in the
Windows app's keychain — a credential that lives solely in the app's keychain
cannot serve an unattended WSL daemon after the app closes or the box reboots.

- Device private key: stored by the **daemon** in its data dir under OS file
  permissions (or the platform key store the daemon can reach unattended),
  zeroized in memory, never logged.
- The Windows app's keychain (M1) holds the *user's* attach bearer, a separate
  secret from the *device* key.
- Service/autostart (M6b): the daemon must load its device key at boot without
  interactive unlock.

## Revocation + lifecycle (receipted)

Every lifecycle operation produces a receipt (T.4) and is attributed to an
authenticated passport, never a body-supplied one:

- register, approve, rotate, revoke (single device), revoke-all (account), unpair,
  account-deletion, failed/replayed attempt.
- **Bounded revocation propagation**: a revoked device key loses access within a
  stated interval (define an SLO in M7b); the daemon re-checks registry state on
  a bounded cadence, not only at connect.

## Threat model / negative tests (M7c gate)

| Threat | Defense | Test |
|---|---|---|
| Stolen/guessed token | PoP over server nonce; a bearer alone is insufficient | wrong-token → denied |
| Replay | Single-use nonce + replay cache | replayed challenge → denied |
| Revoked passport still acting | Registry re-check within SLO | revoke → access lost within bound |
| Unpaired daemon reaching the account | No registry entry → no access | unpaired → denied |
| Cross-tenant | Registry entry is account/tenant-scoped | device of tenant A → no B access |
| Device loss | revoke-all + rotate | mass-revoke → all devices of account lost |
| Cloneable credential | Asymmetric PoP (private key never sent) | captured traffic cannot re-auth |
| Secret in logs/files | daemon-held key, zeroized, never logged | log/disk scan shows no key/bearer |

## Scope split

- **M7a (this doc):** protocol + threat model + custody + revocation design — done.
- **M7b (Engine repo):** device-registry schema/API (account/tenant binding,
  register/list/rotate/revoke/unpair, migrations, receipts). No such route/table
  exists in the deployed Engine API today (verified) — net-new; buildable in the
  Engine repo.
- **M7c (staging, operator-gated):** end-to-end pairing against a staging Engine
  with the negative-test matrix above.

M8 (relay + hosted viewer) is a separate downstream plan and depends on M7's
device identity + a newly-allocated relay OD (**OD-41**).
