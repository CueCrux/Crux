# CueCrux Trust Contract v1.0

The Crux daemon is expected to satisfy the CueCrux Trust Contract:

- free-tier operation is local-first, CPU-only, accountless, and offline-capable
- wire egress is capability-token gated
- local documents remain on the daemon unless a token explicitly authorises the relevant data class
- every call produces a receipt with the token-selected receipt class
- community mods cannot bypass token policy

The canonical contract text lives in `PlanCrux/docs/handbook/CueCrux-Trust-Contract-v1_0.md` in the CueCrux planning repository.
