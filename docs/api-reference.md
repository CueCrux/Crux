# API Reference

Crux Daemon exposes three network surfaces by default:

- HTTP API on `14800`
- gRPC API on `4007`
- Built-in MCP server on `14801` when `CORECRUXD_MCP_ENABLED=true` (default)

## HTTP Endpoints

### Infrastructure

| Method | Path | Description | Auth Scope |
|--------|------|-------------|------------|
| GET | `/healthz` | Health check with build metadata | None |
| GET | `/readyz` | Readiness probe (lock held, routing loaded, capacity OK) | None |
| GET | `/metrics` | Prometheus metrics | None |
| GET | `/v1/version` | Build version, feature flags, sync posture, and cached git update status (`current`, `behind`, `ahead`, `diverged`, `disabled`, `unavailable`, or `error`) | None |

### Query & Retrieval

| Method | Path | Description | Auth Scope |
|--------|------|-------------|------------|
| POST | `/v1/query/text-search` | BM25 text search with token budget and coverage scoring | `query:read` |
| POST | `/v1/query/text-search/expand` | Progressive retrieval — expand scan results with full content | `query:read` |
| POST | `/v1/query/graph-expand` | Graph traversal from seed artifacts with budget | `query:read` * |
| POST | `/v1/query/time-range` | Temporal range query over artifact state changes | `query:read` * |

\* Requires a dataplane-enabled deployment. Returns 501 in Crux Daemon.

### Fact Store

| Method | Path | Description | Auth Scope |
|--------|------|-------------|------------|
| PUT | `/v1/facts` | Store or update a shared fact (entity + key + value + confidence) | `query:read` |
| PUT | `/v1/facts/bulk` | Bulk-store multiple facts | `query:read` |
| GET | `/v1/facts` | Query facts by text with token budget | `query:read` |
| GET | `/v1/facts/{factId}` | Retrieve a specific fact by ID | `query:read` |
| DELETE | `/v1/facts/{factId}` | Delete a fact | `query:read` |
| GET | `/v1/facts/entity/{entity}` | List all facts for an entity | `query:read` |

HTTP fact writes do not support `private=true`. Private facts and per-agent
visibility are MCP-only features.

### Work and Orchestrators

Work and orchestrator records are authority-sensitive, tenant-scoped surfaces.
In JWT modes, creator/updater/commenter identity and tenant come from verified
claims; matching body fields are compatibility constraints, not an
impersonation mechanism. A caller cannot list, read, mutate, comment on, attach
members to, or resolve gates for another tenant.

In local `off`/`dev_scopes` mode, an explicit passport header or matching body
assertion is recorded as `operator:unverified:<id>`. It is not a verified human
identity: work state changes always queue for review. Human gate decisions in
authenticated modes require `facts:write`, a canonical JWT `passport_id`, and
the work tenant; MCP agent tokens and `sub`-only JWTs cannot approve or reject.
An unmapped MCP agent token is attributed as `agent:<token-name>` and is gated
as automation; only an explicit `CRUX_AGENT_PASSPORTS` mapping may resolve it
to a real passport id.

The generic `/v1/entities/{kind}/{id}` and MCP `entity_*` APIs reject governed
`orchestrator` and `punchcard` records and omit both from unfiltered listings.
Use the typed `/v1/orchestrators` and `/v1/punchcards` routes so tenant, actor,
lease-owner, and force-release checks cannot be bypassed.

### Session Store

| Method | Path | Description | Auth Scope |
|--------|------|-------------|------------|
| PUT | `/v1/sessions/{sessionId}/state` | Store session state (JSON blob) | `query:read` |
| GET | `/v1/sessions/{sessionId}/state` | Retrieve session state | `query:read` |

### Event Append

| Method | Path | Description | Auth Scope |
|--------|------|-------------|------------|
| POST | `/v1/admin/append` | Append events to a stream (`/v1/append` compatibility alias) | `admin:write` * |

\* Requires a dataplane-enabled deployment. Returns 501 in Crux Daemon.

### CROWN Receipts

| Method | Path | Description | Auth Scope |
|--------|------|-------------|------------|
| GET | `/v1/receipts/{receiptId}` | Retrieve a CROWN receipt body | `events:read` |
| GET | `/v1/receipts/{receiptId}/signature` | Retrieve receipt Ed25519 signature | `events:read` |
| GET | `/v1/receipts/{receiptId}/verification` | Verify receipt signature and chain | `events:read` |

### Credits

| Method | Path | Description | Auth Scope |
|--------|------|-------------|------------|
| POST | `/v1/credits/spend` | Default-off comped-wallet spend rail. Requires `CORECRUXD_CREDIT_METER=1`; consumes a pinned quote, reserves/spends seeded credits idempotently, and returns a signed `crux.credit_spend_receipt.v1`. Does not mint fiat credits or call Paddle. | `admin:write` |

When `CORECRUXD_CREDIT_METER=1`, successful RCX-verified `POST /v1/gpu1/rerank`
calls also reserve and spend 3 comped-wallet credits. The pinned
`crux.credit_quote.v1` rides at `options.credit_quote`; the
`crux.gpu1.compute_response.v1` envelope adds `credit_spend_receipt`,
`credits_spent`, and `wallet_balance`. Failed/degraded compute releases the
reservation and emits no spend stamp.

### Replay Exports

| Method | Path | Description | Auth Scope |
|--------|------|-------------|------------|
| GET | `/v1/replay/exports/receipts/{receiptId}` | Export receipt bundle (ZIP/TAR+ZST) | `events:read` |
| GET | `/v1/replay/exports/answers/{answerId}` | Export answer bundle | `events:read` |
| GET | `/v1/replay/exports/actions/{actionId}` | Export action bundle | `events:read` |
| GET | `/v1/replay/exports/streams/{streamType}/{streamId}` | Export stream bundle | `events:read` |

### Self-Observation (crux-observe)

| Method | Path | Description | Auth Scope |
|--------|------|-------------|------------|
| GET | `/v1/ops/facts` | Query operational facts | `admin:read` |
| GET | `/v1/ops/errors` | Query recent errors since timestamp | `admin:read` |
| GET | `/v1/ops/health` | Operational health summary | `admin:read` |
| POST | `/v1/bootstrap/pull` | Pull bootstrap facts with token budget | `admin:read` |
| GET | `/v1/bootstrap/status` | Check bootstrap seeded state | `admin:read` |

### Projections

| Method | Path | Description | Auth Scope |
|--------|------|-------------|------------|
| GET | `/v1/projections/entity/count` | Entity count by tenant | `query:read` * |
| GET | `/v1/projections/entity/timeline` | Entity state timeline | `query:read` * |
| GET | `/v1/projections/entity/current-state` | Current entity state | `query:read` * |
| GET | `/v1/admin/projections/meta` | Projection cursor metadata per shard | `admin:read` * |
| POST | `/v1/admin/projections/rebuild` | Trigger projection rebuild | `admin:write` * |
| GET | `/v1/admin/projections/artifacts/{artifactId}/state` | Artifact living state | `admin:read` * |
| GET | `/v1/admin/projections/artifacts/{artifactId}/relations` | Artifact relations | `admin:read` * |
| GET | `/v1/admin/projections/artifacts/{artifactId}/dependents` | Artifact dependents | `admin:read` * |
| GET | `/v1/admin/projections/artifacts/{artifactId}/pressure-events` | Artifact pressure events | `admin:read` * |

\* Requires a dataplane-enabled deployment. Returns 501 in Crux Daemon.

### Repos & Code Map

AST-derived code structure for registered repositories. Registration with a
`root_path` runs a one-shot scan (Rust natively; TS/TSX/Vue/Python via
tree-sitter) and persists it; the repo watch loop re-indexes on change. The
codemap endpoint is the read side — the daemon serving its own code
understanding back to agents.

| Method | Path | Description | Auth Scope |
|--------|------|-------------|------------|
| GET | `/v1/repos?tenant_id=…` | List registered repos for a tenant | `admin:read` |
| POST | `/v1/repos` | Register a repo (`root_path` scans now; `clone_url` defers) | `admin:write` |
| GET | `/v1/repos/{repoId}?tenant_id=…` | One registration | `admin:read` |
| DELETE | `/v1/repos/{repoId}?tenant_id=…` | Unregister (stops watch) | `admin:write` |
| GET | `/v1/repos/{repoId}/codemap?tenant_id=…&format=summary\|full` | AST code map: `summary` = stats + per-crate rollup; `full` = files, symbols, deps, routes | `admin:read` |
| POST | `/v1/workspace/scan` | Scan the daemon's own workspace (`CORECRUXD_WORKSPACE_PATH`) | `admin:write` |
| GET | `/v1/workspace/scan` | Latest self-scan in full | `admin:read` |
| GET | `/v1/workspace/storyline?format=tree\|json` | Per-route call trees from the self-scan | `admin:read` |

### Routing & Shards

| Method | Path | Description | Auth Scope |
|--------|------|-------------|------------|
| GET | `/v1/shards` | List shards with store status | `admin:read` |
| GET | `/v1/shard-map` | Current shard map (shard → node assignment) | `admin:read` |
| GET | `/v1/route` | Route a stream to its owning shard | `admin:read` |
| GET | `/v1/routing/route` | Debug route resolution | `admin:read` |
| GET | `/v1/routing/status` | Routing table version and reload status | `admin:read` |
| GET | `/v1/gpus` | GPU inventory | `admin:read` * |

\* Requires a dataplane-enabled deployment. Returns 501 in Crux Daemon.

### Admin & Operations

| Method | Path | Description | Auth Scope |
|--------|------|-------------|------------|
| POST | `/v1/admin/shard-map` | Update shard map | `admin:write` |
| GET | `/v1/admin/control` | Current control state | `admin:read` |
| POST | `/v1/admin/restart` | Request daemon process restart | `admin:write` |
| GET | `/v1/admin/ops-log` | Structured operations log | `admin:read` |
| POST | `/v1/admin/valves` | Set valve states (throttle, pause, emergency brake) | `admin:write` |
| GET | `/v1/admin/replication/status` | Replication topology status | `admin:read` * |
| POST | `/v1/admin/actions` | Submit admin action (seal, scrub, verify, rebalance) | `admin:write` |
| GET | `/v1/admin/actions/{actionId}` | Get admin action status | `admin:read` |
| POST | `/v1/admin/stream-meta` | Update stream metadata | `admin:write` * |
| POST | `/v1/internal/replication/segments` | Receive replicated segments | `replication:write` * |

\* Requires a dataplane-enabled deployment. Returns 501 in Crux Daemon.

---

## gRPC Services

Default port: `4007`. Proto files in `proto/`.

### CoreCruxDataPlaneV1

All RPCs return `UNIMPLEMENTED` in Crux Daemon and require a dataplane-enabled deployment.

| RPC | Request | Response | Description |
|-----|---------|----------|-------------|
| `AppendBatch` | `AppendBatchRequest` | `AppendBatchResponse` | Append events with deduplication |
| `ReadStream` | `ReadStreamRequest` | stream `ReadStreamResponse` | Read events from a stream |
| `ReadStreamBatched` | `ReadStreamBatchedRequest` | stream `ReadStreamBatchResponse` | Batched read with configurable limits |
| `ReadStreamBatchedUnary` | `ReadStreamBatchedRequest` | `ReadStreamBatchResponse` | Unary batched read |
| `ReadManyBatchedUnary` | `ReadManyBatchedRequest` | `ReadManyBatchedResponse` | Read multiple streams in one call |
| `ReadManyFramesBatchedUnary` | `ReadManyFramesBatchedRequest` | `ReadManyFramesBatchedResponse` | Read raw frames from multiple streams |
| `ReadFramesBatchedUnary` | `ReadStreamBatchedRequest` | `ReadFramesBatchRawResponse` | Raw frame read |
| `ReplaySession` | stream `ReplaySessionRequest` | stream `ReplaySessionResponse` | Bidirectional streaming replay |
| `ReadFrames` | `ReadFramesRequest` | stream `ReadFramesResponse` | Stream raw frame bytes |

### CoreCruxExportV1

| RPC | Request | Response | Description |
|-----|---------|----------|-------------|
| `ExportReceiptBundle` | `ExportReceiptBundleRequest` | stream `ExportChunk` | Stream large export bundles |

Returns `UNIMPLEMENTED` in Crux Daemon.

### CoreCruxObserveV1

| RPC | Request | Response | Description |
|-----|---------|----------|-------------|
| `QueryOpsFacts` | `QueryOpsFactsRequest` | `QueryOpsFactsResponse` | Query operational facts |
| `QueryOpsErrors` | `QueryOpsErrorsRequest` | `QueryOpsErrorsResponse` | Query error log |
| `GetOpsHealth` | `GetOpsHealthRequest` | `GetOpsHealthResponse` | Health summary (JSON) |
| `BootstrapPull` | `BootstrapPullRequest` | `BootstrapPullResponse` | Bootstrap fact pull with token budget |
| `GetBootstrapStatus` | `GetBootstrapStatusRequest` | `GetBootstrapStatusResponse` | Seeded state and fact count |

---

## MCP (JSON-RPC over HTTP)

Endpoint: `GET/POST http://<host>:14801/mcp`

- `GET /mcp` returns server info and protocol metadata.
- `POST /mcp` serves JSON-RPC 2.0 requests such as `tools/list` and
  `tools/call`.
- If `CRUX_AGENT_TOKEN` or `CRUX_AGENT_TOKENS` is configured, MCP requests
  must include `Authorization: Bearer <token>`.
- `Accept: text/event-stream` opens a Streamable HTTP SSE stream. SSE streams
  use the same bearer-token rule, validate `Mcp-Session-Id`, and are capped by
  `CRUX_MCP_SSE_MAX_SESSIONS` and
  `CRUX_MCP_SSE_MAX_SESSIONS_PER_OWNER`.
- Private facts, agent-scoped sessions, and handoff workflows are available
  through MCP tools, not the HTTP `/v1/facts` surface.
- `sync_status` tells agents whether the node is local-only, sync-enabled, or
  degraded before they attempt hosted-platform integration.
- `update_status` tells agents whether the local checkout is current, behind,
  ahead, diverged, disabled, unavailable, or erroring before they propose an
  upgrade or restart.

See [agent-guide.md](/home/myles/CueCrux/Crux/docs/agent-guide.md) and
[examples/mcp-configs/README.md](/home/myles/CueCrux/Crux/examples/mcp-configs/README.md)
for JSON-RPC examples and client configs.

---

## Authentication

Configured via `CORECRUXD_AUTH_MODE`:

| Mode | Description | Use Case |
|------|-------------|----------|
| `off` | No authentication | Local development only |
| `dev_scopes` | Scopes parsed from header, no signature verification | Development/testing |
| `jwt_hs256` | JWT with HMAC-SHA256 signature | Simple production setups |
| `jwt_jwks` | JWT with JWKS key rotation | Production with key management |

Scopes are passed via `Authorization: Bearer <token>` header. Required scopes are listed per endpoint above.
`X-Corecrux-Passport-Id` is only an unverified local assertion in `off` and
`dev_scopes`; production authority must come from verified token claims.

### HTTP fact tenant isolation (`CORECRUXD_TENANT_WRITE_STAMP`)

In `jwt_hs256` and `jwt_jwks` modes, the default is `on`: affected HTTP
fact-backed writes stamp the verified JWT tenant and reads filter to the same
tenant. A token with one tenant needs no selector. On tenant-implicit routes, a
token with multiple tenants or a wildcard tenant must send
`X-Corecrux-Tenant-Id`; an explicit route/body tenant is itself a selector and
must agree with that header when both are present. A missing tenant claim,
ambiguous selection, mismatch, or unauthorized selection is rejected. The
separately documented raw-admin fact reads remain intentionally cross-tenant.
The policy is parsed once at startup, and an invalid value aborts startup.

`off` is a deliberate legacy migration override: reads and writes use the
shared `default` tenant even when JWT claims differ. `shadow` preserves that
same storage behaviour while logging requests that `on` would move or reject.
Historical `default` rows are not migrated automatically.

This switch covers wired HTTP fact-backed surfaces, including generic and
console facts, context recall, engram overlays, memory candidates, result
envelopes, replay capsules, and their paired HTTP audit/export reads. It is not
a universal daemon tenant switch: the MCP compatibility plane still uses
`default`, while entity, edge, session, projection, and other control stores
retain their own tenant contracts.

### Route authorization gate (`CORECRUXD_ROUTE_AUTH`)

Independently of `CORECRUXD_AUTH_MODE`, the daemon runs a deny-by-default route
authorization layer as HTTP middleware, in front of (and in addition to) the
per-handler scope checks. It maps every routed request to a route contract — the
accepted (any-of) scope set for that route template and method — and is
controlled by `CORECRUXD_ROUTE_AUTH` (read once at startup):

| Value | Behaviour |
|-------|-----------|
| `off` | Pass-through; the middleware does nothing. |
| `shadow` | Evaluates the contract and logs a structured `route_auth_shadow_mismatch` warning on any would-deny, but never blocks. It is the derived default only for auth-off, loopback-only operation; otherwise it is an explicit migration override. |
| `enforce` | Public routes (`/healthz`, `/readyz`, `/metrics`, `/session`, `/invocation/verify`, `/v1/openapi.json`, `/v1/version`, `/v1/witness/smoke`, and the `/v1/auth/*` bootstrap rails) pass with no auth headers. Every other route requires one of its contract scopes via the same primitive the handlers use. A route with **no** contract entry — or a request axum could not match to a route template — **fails closed with `403`**. |

`POST /invocation/verify` being public does not make its result an
authentication decision. It reports `structurally_consistent` for the local
self-hash, parent link, capability, and channel checks, together with
`authenticity_verified: false`, `replay_checked: false`, and
`verification_scope: "local_structural_integrity"`. It does not validate the
optional signature/key ID, session identity, timestamps, execution evidence,
outcome, or uniqueness.

With the variable unset, authentication enabled or a non-loopback listener
selects `enforce`; only auth-off plus loopback derives `shadow`. An empty or
unknown explicit value also selects `enforce` and emits a startup warning.

The gate authorizes scopes only; feature-flag gating for optional surfaces stays
in the handler. When `CORECRUXD_AUTH_MODE=off`, the scope check is a no-op (there
is nothing to enforce), but `enforce` still fails closed on uncontracted routes.

---

## Error Format

All HTTP errors use [RFC 7807 Problem Details](https://www.rfc-editor.org/rfc/rfc7807):

```json
{
  "type": "https://errors.cuecrux.com/bad-request",
  "title": "Bad Request",
  "status": 400,
  "detail": "query must not be empty"
}
```

See `docs/error-catalogue.md` for the full error code reference.
