# CueCrux Trust Contract v1.0

The Crux daemon is expected to satisfy the CueCrux Trust Contract:

- free-tier operation is local-first, CPU-only, accountless, and offline-capable
- wire egress is capability-token gated
- local documents remain on the daemon unless a token explicitly authorises the relevant data class
- every call produces a receipt with the token-selected receipt class
- community mods cannot bypass token policy

This file is the canonical Trust Contract text. Release bundles include it next to `LICENCE.md` so operators inherit the same posture every Crux daemon claims to satisfy.

## Repository scope

The contract above is what the *local daemon* in this repository guarantees. Every clause is verifiable by reading the source — the receipt verifier, the capability-token spine, the JWT auth path, the `vaultcrux-local` content-signature gate, and the `crux-router` decision matrix all live in this tree.

The hosted VaultCrux API that `crux-sync` optionally pushes to is operated by CueCrux Ltd and is **not** in this repository. Self-hosted deployments without the hosted backend run in local-only mode (`DegradedLocal` decisions on hosted-tier capabilities); the trust contract above still holds end-to-end for the local half. Audit the hosted half via the published Trust Contract and the receipts your daemon emits, not via this source tree.
