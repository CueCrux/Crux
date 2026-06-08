# Crux Response Contract v1 (CRC-v1)

**Status:** M0 — spec frozen. Canonical home for the portfolio-wide response contract.
**ExecPlan:** `PlanCrux/.agent/execplans/crux-response-contract-v1-default-schema-2026-06-08.md`
**Oracle:** [`crc-v1.schema.json`](crc-v1.schema.json) is the single source of truth. Every emitting endpoint serialises through it; CI validates real responses against it; the daemon serves it verbatim via `get_bootstrap(topic="tool-output")`.

## What it is

A unified, **pointer-first, progressively-hydrated** response envelope shared across CoreCrux `/v1/query/*`, VaultCrux `/v1/memory/retrieve`, and the Crux daemon HTTP + MCP surface. Instead of every endpoint stuffing full content in an ad-hoc JSON shape (~56K tok/q on the LME bench), a CRC-v1 response returns **cheap pointers + a cost_estimate + an agent_decision + a freshness/receipts envelope**, and the caller hydrates only what it needs (~1.6–7.5K tok/q at equal recall — see `AuditCrux/reports/lme-s-agentnative-token-efficiency-CONSOLIDATED.md`).

## The negotiation channel (why this is back-compat-safe)

CRC-v1 is **opt-in per request**, never a silent flag flip. A response is CRC-v1 **only** when the caller asked for it:

| Surface | How to negotiate |
|---|---|
| HTTP | `Accept-Contract: crc-v1` request header (or `?contract=v1`) |
| MCP tool call | `contract: "v1"` argument, or once-per-session via `cuecrux_session(contract="v1")` |

If the caller does **not** negotiate, the endpoint returns its **current legacy shape, byte-identical** — preserving CROWN receipt byte-identity and every existing client. This sidesteps the receipt-stability blocker that stalled the earlier `FEATURE_CORECRUX_AGENT_PAYLOAD_V1` default-on attempt.

`default-on` per endpoint (legacy callers also get CRC-v1) is a **separate operator human-gate** (M6, `eu-ai-act` profile), flipped one endpoint at a time.

## Shape (see the schema for the authority)

```jsonc
{
  "contract": "crc-v1",
  "kind": "search" | "addressed" | "fact" | "session",
  "hydrate_tier": "pointer" | "summary" | "full",   // CRC-v1 default = pointer
  "pointers": [ { "id", "score", "epitome<=40tok", "reason" } ],
  "content":  [ { "id", "text", "token_count" } ],   // ABSENT at pointer tier
  "cost_estimate": { "pointer": N, "summary": N, "full": N },
  "agent_decision": { "load_bearing_lane", "fused_confidence", "suggested_next_lane",
                      "lane_attribution", "read_pointers" } | null,   // null unless kind=search
  "envelope": { "freshness": {...}|null, "receipts_used", "memories_used",
                "autonomy_consumed", "links": { "verify", "open_in_console" } },
  "next": { "expand", "resolution_pointer", "canonical_slug" },
  "meta": { ... per-endpoint diagnostics ... }
}
```

### Per-`kind` field presence

| field | search | addressed | fact | session |
|---|---|---|---|---|
| `pointers` | ✅ | ✅ | — | — |
| `content` (at summary/full) | ✅ | ✅ | ✅ (value) | ✅ (state) |
| `cost_estimate` | ✅ required | ✅ | optional | optional |
| `agent_decision` | ✅ non-null | null | null | null |
| `envelope.freshness` | — | optional | ✅ required | optional |
| `next.canonical_slug` | optional | optional | ✅ | ✅ |

`addressed` = content-pointer hydration (`fetch-content` / `query_expand`): chunk bodies don't decay, so freshness/slug are optional. `fact` = fact-store resolve where decay/supersession is the whole point, so `envelope.freshness` is required.

**Addressed recall is first-class:** `kind=addressed|fact|session` is an exact key resolve and is **never routed through the BM25 ranker**. It echoes `next.canonical_slug` so the next turn re-addresses by key (cheap, exact) instead of re-searching (fuzzy, lossy), and carries `envelope.freshness` so a re-verify turn is unnecessary.

## Invariants (enforced by the schema + per-repo tests)

1. `hydrate_tier=pointer` ⇒ `content` absent/empty (the cheap default actually stays cheap).
2. `kind=search` ⇒ `pointers` and `cost_estimate` present.
3. Legacy (no negotiation) responses are **byte-identical** to pre-CRC-v1 (per-repo golden test; not expressible in this schema).
4. The schema served by `get_bootstrap("tool-output")` is **this exact file** — drift between schema, serializer, and bootstrap seed is the failure mode M4 guards.

## Vendoring

Repos that emit CRC-v1 (CoreCrux, VaultCrux) vendor a copy of `crc-v1.schema.json` and run `validate_crc_v1.py` against representative responses in CI. The canonical copy lives here; vendored copies are checked byte-equal in CI.

## Validate

```bash
python3 validate_crc_v1.py crc-v1.schema.json fixtures/*.json
```
