# Passport Mint Requests — operator runbook

Agent-requested, operator-approved passport minting. When an agent hits a category-enforcement 403
("passport '…' pre-dates the category field, or is unknown"), it can **request** a passport mint; an operator
**approves it in the console** with a category (defaults pre-filled), and the daemon mints a category-scoped
passport for that agent — attributed to the approving operator's passport.

Feature: `CORECRUXD_FEATURE_PASSPORT_MINT_REQUESTS` (default **OFF**). ExecPlan
`crux-passport-mint-request-gate-2026-07-17`. Landed M1–M3 (PRs #467/#470/#471).

## The flow

```
agent (category-403) ──request_passport_mint──▶ pending record (__mint_request__::<id>, born-private)
                                                        │
                                          console "Pending mints" panel (#/, cx-mints)
                                                        │  operator: pick category + name, Accept
POST /v1/passport/mint-requests/<id>/approve ◀──────────┘
   → mints for the REQUESTER with EXACTLY the approved category
     (create_passport if no daemon record, else update_passport(category))
   → records resolved_by_passport = operator; request → approved
                                                        │
requester's next write in that category ──────────────▶ 200 (was 403)
```

## Surface

| Piece | Where |
|---|---|
| MCP tool `request_passport_mint` | `crux-mcp` — self-scoped (requester = caller); args `{requested_category?, reason?}`; flag-gated |
| `GET /v1/passport/mint-requests/pending` | `corecruxd` HTTP, scope `admin:read` |
| `POST /v1/passport/mint-requests/{id}/approve` | scope `admin:write`; body `{approver_passport, category?, name?}` |
| `POST /v1/passport/mint-requests/{id}/reject` | scope `admin:write`; body `{approver_passport}` |
| Console "Pending mints" panel | `console/v2` `cx-mints` (operator-only) |

## Security invariants (do not weaken)

- **Self-scope**: a request is always for the calling agent's own identity — no target-identity argument.
- **Operator approval mandatory**: nothing mints until an explicit `approve` call with an `approver_passport`;
  no auto-mint, no timeout auto-approve (eu-ai-act Art.14).
- **Least privilege**: the minted passport's category equals **exactly** the operator-approved category —
  never broader. `personal | work | public` only.
- **Reject / non-pending / flag-off** mint nothing.
- **Born-private**: pending requests live under the daemon-owned `__mint_request__::` reserved prefix
  (never pushed to a remote; not forgeable by generic client writes).
- **Attributed**: `resolved_by_passport` is the operator; the passport write is receipted at the store layer.

## M4 — canary end-to-end verification

Run against a **non-prod** daemon built from `main` (has M1–M3), flag ON, isolated data dir + port.

```bash
# 1. Stand up the canary (isolated; do NOT point at prod data)
CORECRUXD_FEATURE_PASSPORT_MINT_REQUESTS=1 \
  <corecruxd> --http-port <ALT> --data-dir /tmp/mint-canary-data ...   # per your daemon launch convention

# 2. Agent files a request (MCP tool against the canary's MCP surface)
#    request_passport_mint { "requested_category": "work", "reason": "ethosclaw ingest" }

# 3. List pending (operator token)
curl -s -H "Authorization: Bearer $ADMIN" http://127.0.0.1:<ALT>/v1/passport/mint-requests/pending | jq

# 4. Operator approves — in the CONSOLE "Pending mints" panel (the human-in-the-loop step),
#    or equivalently:
curl -s -X POST -H "Authorization: Bearer $ADMIN" -H 'content-type: application/json' \
  -d '{"approver_passport":"<operator>","category":"work","name":"EthosClaw agent"}' \
  http://127.0.0.1:<ALT>/v1/passport/mint-requests/<id>/approve | jq

# 5. Verify enforcement round-trip: the requester now writes a `work` entity (200),
#    and a `personal` entity still 403s.
```

**Gate:** request → console-approve → the requester's `work` write succeeds and a `personal` write 403s;
`resolved_by_passport` is the operator; reject mints nothing. (The backend request→approve→round-trip is
already covered by the M2 integration tests; this canary proves it on a live daemon + the console UI.)

## EthosClaw ingest unblock (motivating case)

EthosClaw's `ingest` (`AuditCrux/benchmarks/ethosclaw`) is blocked writing audit facts to the tailnet daemon
because its `agent:anthropic` identity has no category (403). Once a mint is approved for `agent:anthropic`
with category `work` (stamps the existing identity — keeps its `CRUX_AGENT_TOKEN`), `ethosclaw ingest
--crux-token <same token>` writes with **no ethosclaw code change** (403 → 200, returns a `fact_id`).

## M5 — production rollout (operator-gated)

**High-risk (identity/auth minting) — requires a passport-attributed human gate per the eu-ai-act profile.**

1. Deploy `main` (with M1–M3) to the target Crux daemon host (`crux` / `100.70.12.73`) — see
   `[[crux-daemon-deploy-host-crux]]`; cut a `v*` tag (the `:latest` image tracks RELEASES).
2. Enable `CORECRUXD_FEATURE_PASSPORT_MINT_REQUESTS=1` in the daemon env **under a human gate**.
   (On host `crux`, use a `zz-` systemd drop-in — a plain drop-in RESETS `EnvironmentFile`, per the
   object-storage deploy trap.)
3. Post-enable smoke: a filed request appears in the prod console "Pending mints"; approve works; the
   passport write is receipted + verifiable.

**Rollback:** disable the flag (the MCP tool disappears, the approve path is inert). Already-minted passports
are unaffected and revocable via existing passport-revocation tooling. No schema-destructive change.
