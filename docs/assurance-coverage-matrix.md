# Assurance & Coverage Matrix — what Crux captures, what a receipt proves

> Status: v1 (2026-07-13, ExecPlan `tier-packaging-and-site-reframe-2026-07-13` M2).
> This is the honesty document. Every claim on a public surface about "evidence"
> must be consistent with this matrix. When in doubt, the matrix wins.

## Terminology (three distinct assurance classes)

1. **Verifiable record** — a CROWN-receipted, hash-chained record signed by a
   key held by the *same trust domain that produced the event* (the daemon, or
   the agent's own passport). Tamper-evident after the fact; offline-verifiable;
   **not** forgery-resistant against a compromise of that same domain. This is
   what the free daemon mints for memory/retrieval operations.
2. **Mediated evidence** — a record minted by a *witness process* that sits on
   the traffic path and holds its **own** signing key the agent never has
   (`crux-llm-shim` local mode; cloud witness mode). A compromised agent cannot
   forge these; it can only avoid them (see "bypass" per row — avoidance is
   detectable absence, not forgeable presence).
3. **External attestation** — counter-signature or anchoring by a party off the
   host (hosted aggregation, transparency-log registration per the SCITT
   mapping). **Not shipped in the free daemon**; the Governance tier's hosted
   aggregation consumes the same record shapes. No Crux surface may imply this
   exists locally.

**Global honesty note:** everything below runs on the operator's host. An
attacker with root on that host can read any local key. Local mediation raises
the bar from "the agent can rewrite its own story" to "only a host-level
compromise can" — it does not eliminate host-level trust. That residual is what
external attestation (class 3) addresses.

## The matrix

| Event class | Captured by (default?) | Trust boundary of capture | Signed with | Bypassable how | A receipt PROVES | A receipt does NOT prove |
|---|---|---|---|---|---|---|
| **Cloud model call — Anthropic `/v1/messages`, OpenAI `/v1/chat/completions`·`/v1/responses`** | Cloud witness mode of `crux-llm-shim` (opt-in: `CRUX_CLOUD_WITNESS=1` + client `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL` → loopback listener) | Witness process, separate from the agent process; dedicated key the agent never holds | Witness Ed25519 key (`witness.key`, 0600) | Agent/user unsets the base-URL env → calls stop appearing in the witness ledger (detectable absence); host-root can read the key | An identified client sent a request with digest X to provider Y at time T and received a response with digest Z, with the recorded model/usage/end-state, **through the witness** | That the agent had no other channel to the provider; anything about content semantics (digests only); that the host itself was uncompromised |
| **Local model call (Ollama/vLLM/llama.cpp)** | `crux-llm-shim` local mode (opt-in: `CRUX_LLM_SHIM=1`) | Same as above (witness class) | Shim receipt records; witness-signed in witness-enabled runs | Client points at the model server directly instead of the shim | Context injected (stable_hash/bundle_digest) + request/response digests + stream end-state through the shim | Same limits as cloud row |
| **Agent tool calls / file edits / shell (Claude Code)** | `crux-observe.sh` hook snippet → `/v1/sessions/{id}/observations` (near-default once installed); `crux-hook observe-pre/post` signed trace nodes with BLAKE3 file before/after (flag-gated) | **Inside the agent's own harness** — hooks run in the agent's environment | Daemon receipts on storage; trace nodes carry hashes | A compromised agent can suppress, reorder, or fabricate hook events **before** they reach the daemon | That the daemon *received and durably stored* these self-reports at time T (storage is class-1 verifiable record) | **What the agent actually did.** This lane is self-reported telemetry, not evidence — never market it as proof of conduct |
| **Codex sessions** | `codex-tailer.py` (opt-in script tailing `~/.codex` rollouts) | Same-host script reading agent-written files | Daemon receipts on storage | Agent/user edits or truncates rollout files before tailing | Daemon received these observations at time T | What the Codex agent actually did (same self-report limit as above) |
| **Memory writes (`store_fact`, `entity_upsert`, `memory_edit/forget/consolidate`)** | Daemon, always on | Daemon process (separate from agent; same host); passport-authenticated writes | Daemon CROWN key (Ed25519, hash-chained journal) | Bypassing the daemon entirely (writing elsewhere) — nothing is claimed about data not in Crux | Which authenticated passport stored/changed what, when; full version/supersession lineage; erasure receipts on forget | That the stored content is *true*; that the acting passport wasn't a stolen credential |
| **Retrieval (`query`, `query_facts`, `query_scan/expand`)** | Daemon, always on | Daemon process | Daemon CROWN key | n/a (reads inside Crux are always receipted) | What was retrieved, under which token budget, by which passport, when — replayable | That the agent *used* the retrieved context in its output |
| **Handoffs (`create_handoff`/`accept_handoff`)** | Daemon, always on | Daemon process | **Keyed BLAKE3 MAC (`blake3-mac-v1`)** — shared-key integrity, *not* portable public-key evidence | Key holders can mint MACs; third parties cannot verify without the key | To key holders: the bundle wasn't altered in transit | Anything to an outside verifier — do not present handoff MACs as signatures |
| **Coordination (work board, announces, leases)** | Daemon coordination plane (flag-gated `CORECRUXD_COORD`) | Daemon process | Daemon receipts | Advisory by design — sessions can simply not announce | What sessions declared, when | What undeclared sessions did |
| **Hosted sync / multi-device (Pro)** | CruxEngine hosted plane (paid, opt-in) | Off-host service | Engine-side signing (separate custody) | Not syncing | Server-side receipt of what was pushed/pulled | Anything about local-only activity |

## Standing rules for public surfaces

1. A **self-signed** CROWN receipt is described as a *verifiable record* — never
   "proof the agent did X". The passport is **identity and constraint**, not
   proof-of-conduct.
2. Only witness-minted records may be called **mediated evidence**, and every
   such claim links the bypass column above.
3. "Flight recorder" language is earned only by surfaces whose coverage this
   matrix actually describes, with the bypass column visible.
4. The observe/hook lane is **telemetry**. It is genuinely useful (timelines,
   debugging, cost attribution) and genuinely not evidence. Keep the classes
   separate everywhere.
