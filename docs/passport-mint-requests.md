# Passport Mint Requests — operator runbook

Agent-requested, operator-approved passport minting. When an agent hits a category-enforcement 403
("passport '…' pre-dates the category field, or is unknown"), it can **request** a passport mint; an operator
**approves it in the console** with a category (defaults pre-filled), and the daemon mints a category-scoped
passport for that agent — attributed to the approving operator's passport.

Feature: `CORECRUXD_FEATURE_PASSPORT_MINT_REQUESTS` (default **OFF**). ExecPlan
`crux-passport-mint-request-gate-2026-07-17`. Landed M1–M3 (PRs #467/#470/#471), with the
production approval boundary hardened in PR #497.

## The flow

```
agent (category-403) ──request_passport_mint──▶ pending record (__mint_request__::<id>, born-private)
                                                        │
                                          console "Pending mints" panel (#/, cx-mints)
                                                        │  operator: pick category + name, Accept
POST /v1/passport/mint-requests/<id>/approve ◀──────────┘
   → mints for the REQUESTER with EXACTLY the approved category
     (create_passport if no daemon record, else update_passport(category))
   → records resolved_by_passport = verified operator; request → approved
   → returns a signed approval receipt that binds the exact passport mutation
                                                        │
requester's next write in that category ──────────────▶ 200 (was 403)
```

## Surface

| Piece | Where |
|---|---|
| MCP tool `request_passport_mint` | `crux-mcp` — self-scoped (requester = caller); args `{requested_category?, reason?}`; flag-gated |
| `GET /v1/passport/mint-requests/pending` | `corecruxd` HTTP, scope `admin:read` |
| `POST /v1/passport/mint-requests/{id}/approve` | verified human JWT, `admin:write`, tenant `default`; body `{category, name?, approver_passport?}`. `category` is mandatory; an approver hint, if supplied, must equal the JWT `passport_id` |
| `POST /v1/passport/mint-requests/{id}/reject` | verified human JWT, `admin:write`, tenant `default`; body `{approver_passport?}` with the same exact-match rule |
| Console "Pending mints" panel | `console/v2` `cx-mints` (operator-only) |

## Security invariants (do not weaken)

- **Self-scope**: a request is always for the calling agent's own identity — no target-identity argument.
- **Verified human approval mandatory**: nothing mints until an explicit `approve` call authenticated by a
  cryptographically verified JWT carrying `passport_id` and `admin:write`. Auth-off, `dev_scopes`, agent tokens,
  passport overrides, and body-only approver claims cannot decide a mint. There is no auto-mint or timeout
  auto-approve (eu-ai-act Art.14).
- **No self-review**: the authenticated operator passport must differ from both `requester_id` and
  `requested_by_passport`.
- **Least privilege**: the minted passport's category equals **exactly** the operator-approved category —
  never broader. `personal | work | public` only. Approval requires an explicit category; the request's suggested
  category is never used as an authorization fallback.
- **Reject / non-pending / flag-off** mint nothing.
- **Born-private**: pending requests live under the daemon-owned `__mint_request__::` reserved prefix
  (never pushed to a remote; not forgeable by generic client writes).
- **Attributed and receipted**: `resolved_by_passport`, fact actors, and the signed approval receipt all bind the
  verified operator. The receipt also binds the request, decision, category, operation, record hash, and mutation
  hash; receipt failure aborts the passport mutation.

## M4 — canary end-to-end verification

Run against a **non-prod** daemon built from `main`, flag ON, isolated data dir + ports, and signed JWT auth.
`off` and `dev_scopes` are deliberately invalid for mint decisions.

```bash
# 1. Stand up the canary (isolated; do NOT point at prod data). Use a fresh
#    >=32-byte HS256 secret, explicit issuer/audience, and loopback-only ports.
CORECRUXD_FEATURE_PASSPORT_MINT_REQUESTS=1 \
CORECRUXD_AUTH_MODE=jwt_hs256 \
CORECRUXD_JWT_HS256_SECRET="$CANARY_JWT_SECRET" \
CORECRUXD_JWT_ISS=mint-canary CORECRUXD_JWT_AUD=corecrux \
CORECRUXD_HTTP_HOST=127.0.0.1 CORECRUXD_HTTP_PORT=<ALT_HTTP> \
CORECRUXD_GRPC_HOST=127.0.0.1 CORECRUXD_GRPC_PORT=<ALT_GRPC> \
CORECRUXD_MCP_HOST=127.0.0.1 CORECRUXD_MCP_PORT=<ALT_MCP> \
CORECRUXD_DATA_DIR="$CANARY_DATA_DIR" \
CRUX_AGENT_TOKENS="requester:$CANARY_AGENT_TOKEN" \
  <corecruxd>

# 2. Agent files a request (MCP tool against the canary's MCP surface)
#    request_passport_mint { "requested_category": "work", "reason": "ethosclaw ingest" }

# 3. List pending with a signed operator JWT carrying admin:read, tenant_id=default,
#    and passport_id=operator-canary. An agent token is not an operator JWT.
curl -s -H "Authorization: Bearer $OPERATOR_JWT" \
  http://127.0.0.1:<ALT_HTTP>/v1/passport/mint-requests/pending | jq

# 4. Operator approves — in the CONSOLE "Pending mints" panel (the human-in-the-loop step),
#    or equivalently. The body hint is optional, but when present must equal the JWT passport_id.
curl -s -X POST -H "Authorization: Bearer $OPERATOR_WRITE_JWT" -H 'content-type: application/json' \
  -d '{"approver_passport":"operator-canary","category":"work","name":"EthosClaw agent"}' \
  http://127.0.0.1:<ALT_HTTP>/v1/passport/mint-requests/<id>/approve | jq

# 5. Verify enforcement round-trip: the requester now writes a `work` entity (200),
#    and a `personal` entity still 403s.
```

**Gate:** request → non-self verified-JWT approve with an explicit category → the requester's `work` write
succeeds and a `personal` write 403s. The response's receipt verifies; `resolved_by_passport` is the JWT
`passport_id`; body/JWT mismatch, self-review, agent-token approval, missing category, reject, and flag-off all
mint nothing. (The backend path is covered by integration tests; this canary proves the live daemon + console.)

## EthosClaw ingest unblock (motivating case)

EthosClaw's `ingest` (`AuditCrux/benchmarks/ethosclaw`) is blocked writing audit facts to the tailnet daemon
because its `agent:anthropic` identity has no category (403). Once a mint is approved for `agent:anthropic`
with category `work` (stamps the existing identity — keeps its `CRUX_AGENT_TOKEN`), `ethosclaw ingest
--crux-token <same token>` writes with **no ethosclaw code change** (403 → 200, returns a `fact_id`).

## M5 — production rollout (operator-gated)

**High-risk (identity/auth minting) — requires a passport-attributed human gate per the eu-ai-act profile.**

1. Cut a forward-only `v*` release and deploy its immutable image to the target Crux daemon host
   (`crux` / `100.70.12.73`). The live service is Docker Compose under `/opt/crux`; it is not systemd-managed.
2. Keep `CORECRUXD_FEATURE_PASSPORT_MINT_REQUESTS=0` for the image cutover and complete health/auth smoke first.
   Then change only that key in `/opt/crux/docker-compose.override.yml` **under a human gate** and force-recreate
   only the `crux` service. Retain an exact pre-change backup and never run `docker compose down -v`.
3. Post-enable smoke: a filed request appears in the prod console "Pending mints"; approve works; the
   passport write is receipted + verifiable.

**Rollback:** disable the flag (the MCP tool disappears, the approve path is inert). Already-minted passports
are unaffected and revocable via existing passport-revocation tooling. No schema-destructive change.
