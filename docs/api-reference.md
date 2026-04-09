# API Reference

CoreCrux Community Edition exposes three network surfaces by default:

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
| GET | `/v1/version` | Build version and compat contract | None |

### Query & Retrieval

| Method | Path | Description | Auth Scope |
|--------|------|-------------|------------|
| POST | `/v1/query/text-search` | BM25 text search with token budget and coverage scoring | `query:read` |
| POST | `/v1/query/text-search/expand` | Progressive retrieval — expand scan results with full content | `query:read` |
| POST | `/v1/query/graph-expand` | Graph traversal from seed artifacts with budget | `query:read` * |
| POST | `/v1/query/time-range` | Temporal range query over artifact state changes | `query:read` * |

\* Requires proprietary edition data-plane. Returns 501 in Community Edition.

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

### Session Store

| Method | Path | Description | Auth Scope |
|--------|------|-------------|------------|
| PUT | `/v1/sessions/{sessionId}/state` | Store session state (JSON blob) | `query:read` |
| GET | `/v1/sessions/{sessionId}/state` | Retrieve session state | `query:read` |

### Event Append

| Method | Path | Description | Auth Scope |
|--------|------|-------------|------------|
| POST | `/v1/admin/append` | Append events to a stream (`/v1/append` compatibility alias) | `admin:write` * |

\* Requires proprietary edition data-plane. Returns 501 in Community Edition.

### CROWN Receipts

| Method | Path | Description | Auth Scope |
|--------|------|-------------|------------|
| GET | `/v1/receipts/{receiptId}` | Retrieve a CROWN receipt body | `events:read` |
| GET | `/v1/receipts/{receiptId}/signature` | Retrieve receipt Ed25519 signature | `events:read` |
| GET | `/v1/receipts/{receiptId}/verification` | Verify receipt signature and chain | `events:read` |

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

\* Requires proprietary edition data-plane. Returns 501 in Community Edition.

### Routing & Shards

| Method | Path | Description | Auth Scope |
|--------|------|-------------|------------|
| GET | `/v1/shards` | List shards with store status | `admin:read` |
| GET | `/v1/shard-map` | Current shard map (shard → node assignment) | `admin:read` |
| GET | `/v1/route` | Route a stream to its owning shard | `admin:read` |
| GET | `/v1/routing/route` | Debug route resolution | `admin:read` |
| GET | `/v1/routing/status` | Routing table version and reload status | `admin:read` |
| GET | `/v1/gpus` | GPU inventory | `admin:read` * |

\* Requires proprietary edition. Returns 501 in Community Edition.

### Admin & Operations

| Method | Path | Description | Auth Scope |
|--------|------|-------------|------------|
| POST | `/v1/admin/shard-map` | Update shard map | `admin:write` |
| GET | `/v1/admin/control` | Current control state | `admin:read` |
| GET | `/v1/admin/ops-log` | Structured operations log | `admin:read` |
| POST | `/v1/admin/valves` | Set valve states (throttle, pause, emergency brake) | `admin:write` |
| GET | `/v1/admin/replication/status` | Replication topology status | `admin:read` * |
| POST | `/v1/admin/actions` | Submit admin action (seal, scrub, verify, rebalance) | `admin:write` |
| GET | `/v1/admin/actions/{actionId}` | Get admin action status | `admin:read` |
| POST | `/v1/admin/stream-meta` | Update stream metadata | `admin:write` * |
| POST | `/v1/internal/replication/segments` | Receive replicated segments | `admin:write` * |

\* Requires proprietary edition data-plane. Returns 501 in Community Edition.

---

## gRPC Services

Default port: `4007`. Proto files in `proto/`.

### CoreCruxDataPlaneV1

All RPCs return `UNIMPLEMENTED` in Community Edition (requires proprietary edition).

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

Returns `UNIMPLEMENTED` in Community Edition.

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
- Private facts, agent-scoped sessions, and handoff workflows are available
  through MCP tools, not the HTTP `/v1/facts` surface.

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
