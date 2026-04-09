# @cuecrux/client

TypeScript client for [CoreCrux Community Edition](https://github.com/CueCrux/Crux).

Zero runtime dependencies -- uses native `fetch` (Node.js >= 18, all modern browsers).

## Installation

```bash
npm install @cuecrux/client
```

## Quick start

```typescript
import { CoreCruxClient } from "@cuecrux/client";

const client = new CoreCruxClient({
  baseUrl: "http://localhost:14800",
  token: "your-bearer-token", // optional
});

// Store a fact
const fact = await client.storeFact({
  entity: "user::alice",
  key: "preferred_language",
  value: "TypeScript",
});
console.log(fact.fact_id, fact.version);

// Query facts with BM25 search
const results = await client.queryFacts({
  query: "TypeScript",
  top_k: 5,
});
console.log(results.facts.length, "matches,", results.total_tokens, "tokens");

// Retrieve facts for an entity
const { facts } = await client.getFactsByEntity("user::alice");

// Delete a fact (soft-delete)
const deleted = await client.deleteFact(fact.fact_id);
```

## Sessions

```typescript
// Store session state (any JSON-serialisable value)
const session = await client.putSession("session-1", {
  step: 3,
  context: { topic: "onboarding" },
});

// Retrieve session state
const restored = await client.getSession("session-1");
if (restored) {
  console.log(restored.state);
}
```

## Text search

```typescript
const search = await client.textSearch({
  tenant_id: "my-tenant",
  query: "deployment architecture",
  limit: 10,
  token_budget: 4096,
});

for (const hit of search.results) {
  console.log(`doc ${hit.doc_id} score=${hit.score} tokens=${hit.token_count}`);
}
console.log("coverage:", search.coverage.score);
```

## Server-Sent Events

Subscribe to real-time fact and session mutations:

```typescript
const es = client.subscribeEvents({ types: ["fact.stored", "fact.deleted"] });

es.addEventListener("fact.stored", (e) => {
  const data = JSON.parse(e.data);
  console.log("Fact stored:", data.fact_id, data.entity, data.key);
});

es.addEventListener("fact.deleted", (e) => {
  const data = JSON.parse(e.data);
  console.log("Fact deleted:", data.fact_id);
});

es.onerror = () => {
  console.error("SSE connection error");
};

// Close when done
es.close();
```

**Node.js note:** `EventSource` is available globally from Node 22+. For Node 18-21,
use a polyfill such as [`eventsource`](https://www.npmjs.com/package/eventsource).

## Authentication

Pass a bearer token in the constructor:

```typescript
const client = new CoreCruxClient({
  baseUrl: "http://localhost:14800",
  token: "crx_your_token_here",
});
```

All HTTP methods include the `Authorization: Bearer <token>` header automatically.

SSE (`subscribeEvents`) uses native `EventSource` which does not support custom
headers. For authenticated SSE, use a polyfill that supports headers or configure
a reverse proxy that injects credentials.

## Error handling

All methods throw `CoreCruxError` on non-2xx responses. The error carries the HTTP
status code and, when the server returns RFC 9457 Problem Details, the full problem
body:

```typescript
import { CoreCruxError } from "@cuecrux/client";

try {
  await client.getFact("nonexistent");
} catch (err) {
  if (err instanceof CoreCruxError) {
    console.error(err.status);           // 404
    console.error(err.message);          // "fact 'nonexistent' not found"
    console.error(err.problem?.type);    // "https://errors.cuecrux.com/not-found"
  }
}
```

Methods that return `null` on 404 (`getFact`, `getSession`) catch the error
internally and return `null` instead of throwing.

## API reference

| Method | HTTP | Description |
|---|---|---|
| `healthz()` | `GET /healthz` | Node health status |
| `readyz()` | `GET /readyz` | Node readiness check |
| `version()` | `GET /v1/version` | Build version and feature flags |
| `storeFact(fact)` | `PUT /v1/facts` | Store a single fact |
| `storeFacts(facts)` | `PUT /v1/facts/bulk` | Store multiple facts |
| `getFact(factId)` | `GET /v1/facts/{factId}` | Get fact by ID |
| `deleteFact(factId)` | `DELETE /v1/facts/{factId}` | Soft-delete a fact |
| `getFactsByEntity(entity)` | `GET /v1/facts/entity/{entity}` | Facts for an entity |
| `queryFacts(options?)` | `GET /v1/facts` | BM25 query over facts |
| `exportFacts(options?)` | `GET /v1/facts/export` | Paginated fact export |
| `putSession(id, state)` | `PUT /v1/sessions/{id}/state` | Store session state |
| `getSession(id)` | `GET /v1/sessions/{id}/state` | Get session state |
| `textSearch(options)` | `POST /v1/query/text-search` | BM25 text search |
| `textSearchExpand(options)` | `POST /v1/query/text-search/expand` | Expand scan results |
| `graphExpand(options)` | `POST /v1/query/graph-expand` | Graph traversal |
| `timeRange(options)` | `POST /v1/query/time-range` | Temporal range query |
| `subscribeEvents(options?)` | `GET /v1/events/stream` | SSE event stream |

## API docs

Full HTTP API documentation is served by the daemon at `/v1/openapi.json`.

## Licence

CueCrux Community Licence (CCL v1.0). See [LICENCE.md](../../LICENCE.md).
