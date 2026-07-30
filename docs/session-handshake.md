# Session Handshake (Crux Daemon)

Crux Daemon supports the VaultCrux Session Handshake v1 protocol — one endpoint
and one MCP tool that together give an agent a receipted plan describing
what it's allowed to do. This document is the operator-facing summary —
where state lives on disk, what the wire formats look like, and how to
authenticate a session-plan signature or check an invocation receipt's
structural consistency outside the daemon. The
canonical protocol invariants are encoded in the `crux-session` crate
([crates/crux-session/src/lib.rs](../crates/crux-session/src/lib.rs)).

## What Crux Daemon Gives You

- **One MCP tool:** `cuecrux_session`. Registered at the head of the
  `tools/list` catalogue; collapses per-service discovery into one call.
- **One HTTP endpoint:** `POST /session` (unversioned path; local-daemon specific,
  matches master-plan §5.1).
- **One verification endpoint:** `POST /invocation/verify`. Decodes a
  hex-encoded invocation receipt and returns a local structural-consistency
  verdict. It does not authenticate the receipt or check replay.
- **Durable session state** under `$CORECRUXD_DATA_DIR`:
  - `.install-uuid` — per-install random UUID; hashed into the principal.
  - `sessions/{session_id}.json` — one sealed plan per session.
  - `session-events.jsonl` — append-only sealed-event log (one JSON line
    per `SessionPlanSealed` or `InvocationReceipted` event).

Plans on Crux Daemon run in `"local"` receipt mode: BLAKE3 hash over canonical
CBOR, no ed25519 signature. Local mode covers integrity; signed plans
are a hosted-only thing because the local-daemon threat model trusts the local
machine.

## Opening a session

```http
POST /session HTTP/1.1
Host: localhost:14800
Content-Type: application/json
Accept: application/json

{
  "client_id": "my-agent",
  "client_version": "1.2.3",
  "accepts": ["application/json"],
  "intent": "document_ingest",
  "hints": { "prefer_bulk": false }
}
```

Response:

```http
HTTP/1.1 200 OK
Content-Type: application/json
X-CueCrux-Session-Id: 0102030405060708090a0b0c0d0e0f10
X-CueCrux-Plan-Hash: b8e1...
Cache-Control: no-store

{ ...SessionPlan... }
```

The response body is the canonical JSON form of the `SessionPlan`; the
`X-CueCrux-Plan-Hash` header mirrors `receipt.hash`. All subsequent calls
that should chain to this session include `X-CueCrux-Session-Id` in their
headers (or the equivalent in MCP metadata).

## What's in a SessionPlan

Fields an agent should care about:

| Field | Meaning |
|---|---|
| `session_id` | Opaque 16-byte ULID; used as the bearer for subsequent calls. |
| `capability_graph` | Array of `{cap, prefer, shape, min_tier, cost_class, impl_path}`. Everything the passport is entitled to invoke this session. |
| `capability_graph_hash` | BLAKE3 over the canonical-CBOR of `capability_graph`. Exposed so MemoryCrux + audit tools can index by surface. |
| `channels` | `{bulk, mcp}` — where to route calls. `bulk` is null on Crux Daemon until Layer 2 ships. |
| `receipt.hash` | BLAKE3 over canonical-CBOR of the plan with `hash`/`signature`/`signer_kid` zeroed. |
| `receipt.mode` | `"local"` on Crux Daemon. `"verified"` on hosted, with an `ed25519` signature over the hash. |
| `intent_hint` | Echoes back the `intent` field from the request, if supplied. |

The Crux Daemon capability graph is shaped by:

1. **Affinity** — the passport has `["*"]` so every catalogue entry
   passes the affinity filter.
2. **Tier** — Crux Daemon runs at tier `"local"`. Catalogue entries with
   `min_tier: "free"` or above are filtered out. Baseline free
   capabilities (`session_context`, `journal_append`, etc.) are in;
   `retrieve` / `proof_document` / `audit_replay` are hosted-only.

## Invocation receipts

Every call made under an active session should produce an
`InvocationReceipt` — a 200-byte receipt chained to the plan via
`parent_plan_receipt_hash`.

To verify one:

```http
POST /invocation/verify HTTP/1.1
Host: localhost:14800
Content-Type: application/json

{
  "invocation_id":            "<16 bytes hex>",
  "session_id":               "<16 bytes hex>",
  "parent_plan_receipt_hash": "<32 bytes hex>",
  "capability":               "retrieve",
  "channel":                  "bulk",
  "invoked_at":               1745000001000,
  "completed_at":             1745000001100,
  "input_hash":               "<32 bytes hex>",
  "output_hash":              "<32 bytes hex>",
  "outcome":                  "ok",
  "receipt_hash":             "<32 bytes hex>"
}
```

Response:

```json
{
  "structurally_consistent": true,
  "authenticity_verified": false,
  "replay_checked": false,
  "verification_scope": "local_structural_integrity",
  "integrity_ok": true,
  "capability_ok": true,
  "channel_ok": true,
  "governance_faults": [],
  "parent_plan_found": true,
  "parent_plan_principal_id": "ce:a4f3b1c2:tester"
}
```

The endpoint returns `200` even when the verdict flags governance faults
(wrong capability, wrong channel). Master-plan §8.2 — faults are
evidence, not reasons to drop the receipt. The caller decides what
enforcement to apply.

`structurally_consistent: true` means only that the receipt self-hash and
parent-plan hash match, and that its capability/channel fit the supplied plan.
The local route does not authenticate `receipt_signature` or `signer_kid`,
validate `session_id`, timestamps/expiry, input/output evidence, or outcome,
and it keeps no invocation-ID replay state. Signature fields are accepted and
shape-decoded for wire compatibility only. Repeating the same receipt can
therefore return `structurally_consistent: true` again while
`authenticity_verified` and `replay_checked` remain `false`. This public route
does not authorize execution.

## On-disk format

Crux Daemon is designed so that an operator can `jq` through state without
spinning up a database:

```bash
# Every session you've ever opened:
ls "$CORECRUXD_DATA_DIR/sessions/"

# Sealed events in write order (1 JSON line each):
cat "$CORECRUXD_DATA_DIR/session-events.jsonl" | jq -r .event_type | sort | uniq -c
```

Session files are rewritten atomically (temp-file + rename) on every
close/revoke; the event log is append-only and fsync'd per write.

## Verifying a receipt offline

The `crux-session` crate's CBOR + BLAKE3 primitives are pure; a verifier
can be built with zero I/O. Sketch:

```rust
use crux_session::{plan_receipt_hash, verify_invocation_receipt, SessionPlan};

let plan = SessionPlan::from_canonical_cbor(&plan_cbor_bytes)?;

// Plan-level integrity:
assert_eq!(plan_receipt_hash(&plan), plan.receipt.hash);

// Invocation-level chain:
let verdict = verify_invocation_receipt(&receipt, &plan);
assert!(verdict.structurally_consistent());
```

The TypeScript mirror at `@cuecrux-shared/session` produces byte-identical
canonical CBOR, so the same structural hash can be reproduced in either
runtime. Byte parity does not establish signer authenticity or replay safety.

## Feature flags

Crux Daemon has no plan-level feature flags at M6 — everything is always on. On
hosted the session feature is gated behind `FEATURE_SESSION_HANDSHAKE`
per tenant; Crux Daemon ships with it enabled by default.

## What's missing (follow-ups)

- **Layer 2 bulk channel.** Crux Daemon surfaces `channels.bulk: null`;
  the HTTP/2 + CBOR bulk transport is a separate plan.
- **Automatic MCP interceptor.** Invocation receipts are minted by an
  agent that chooses to chain them; there is no built-in trap-door that
  silently mints one for every tool call. See the M4 deferred-to-follow-up
  note in the ExecPlan.
- **Hosted import migration.** The import event type and the
  `imported_principal_map` table are pre-positioned for Phase 8; the
  actual upload pipeline is not yet wired. The persisted `ce:` principal
  prefix remains as a wire-compatibility identifier for existing local
  receipts.
