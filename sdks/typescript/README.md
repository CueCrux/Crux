# @cuecrux/client

TypeScript client for [Crux Daemon](https://github.com/CueCrux/Crux).

Zero runtime dependencies -- uses native `fetch` (Node.js >= 18, all modern browsers).

## Installation

```bash
npm install @cuecrux/client
```

## Quick start

```typescript
import { CueCruxClient } from "@cuecrux/client";

const client = new CueCruxClient({
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

## Context bundle

`GET /v1/context` is the provider-neutral injection bundle — the same memory the
Claude Code boot banner uses, in a shape any harness can inject. Requires
`CORECRUXD_CONTEXT_SURFACE=1` on the daemon (the route 404s when it is off).

```typescript
const bundle = await client.context({ entity: "execplan:my-plan", token_budget: 2000 });
for (const section of bundle.sections) {
  console.log(section.kind, section.est_tokens);
}

// `stable_hash` covers the ordered sections only, so it is byte-stable while
// the fact chain is unchanged — that is what makes provider prompt caches hit.
console.log(bundle.stable_hash);

// Ready-made renderings:
const markdown = await client.contextMarkdown({ entity: "execplan:my-plan" });
const { messages } = await client.contextMessages({ entity: "execplan:my-plan" });
```

## Review, consolidation and ingest

```typescript
// Mine transcript text into review candidates. They land in a review namespace
// and never reach recall until promoted.
const { candidates } = await client.extractMemory({ text: transcript });
await client.promoteCandidate(candidates[0].candidate_id, { reviewer: "me" });

// Merge duplicates atomically, with a signed diff receipt. Every target must
// live under the one (entity, key) being consolidated.
const merged = await client.consolidate({
  entity: "project",
  key: "status",
  canonical_value: "shipped",
  target_fact_ids: [factA.fact_id, factB.fact_id],
});
await client.undoConsolidation({ canonical_fact_id: merged.receipt.canonical_fact_id });

// Ingest documents; chunks without a dense_vector are embedded server-side.
await client.localIngest({
  tenant_id: "my-tenant",
  corpus_id: "notes",
  documents: [{ doc_id: "d1", chunks: [{ chunk_id: "c1", text: "..." }] }],
});
```

## Server-Sent Events

`streamEvents` is the recommended path — it is built on `fetch`, so it needs no
`EventSource` global and no polyfill, and unlike `EventSource` it can send the
`Authorization` header:

```typescript
const controller = new AbortController();

for await (const event of client.streamEvents({
  types: ["fact.stored", "fact.deleted"],
  signal: controller.signal,
})) {
  console.log(event.type, event);
  break; // the stream is infinite; break or abort to disconnect
}
```

`subscribeEvents` remains for browsers that want a real `EventSource`:

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

**Node.js note:** `EventSource` is still not a Node global in 22.x, so
server-side callers need a polyfill such as
[`eventsource`](https://www.npmjs.com/package/eventsource) — or, more simply,
`streamEvents` above. `EventSource` also cannot send custom headers, so it
cannot authenticate against a daemon with auth on.

## Authentication

Pass a bearer token in the constructor:

```typescript
const client = new CueCruxClient({
  baseUrl: "http://localhost:14800",
  token: "crx_your_token_here",
});
```

All HTTP methods include the `Authorization: Bearer <token>` header automatically.

SSE (`subscribeEvents`) uses native `EventSource` which does not support custom
headers. For authenticated SSE, use a polyfill that supports headers or configure
a reverse proxy that injects credentials.

## Error handling

All methods throw `CueCruxError` on non-2xx responses. The error carries the HTTP
status code and, when the server returns RFC 9457 Problem Details, the full problem
body:

```typescript
import { CueCruxError } from "@cuecrux/client";

try {
  await client.getFact("nonexistent");
} catch (err) {
  if (err instanceof CueCruxError) {
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
| `context(options?)` | `GET /v1/context` | Provider-neutral injection bundle |
| `postContext(options?)` | `POST /v1/context` | Same bundle, options in the body |
| `contextMarkdown(options?)` | `GET /v1/context?render=markdown` | Boot-banner rendering (text) |
| `contextMessages(options?)` | `GET /v1/context?render=openai_messages` | OpenAI messages fragment |
| `extractMemory(options)` | `POST /v1/memory/extract` | Mine text into review candidates |
| `listCandidates(status?)` | `GET /v1/memory/candidates` | List review candidates |
| `promoteCandidate(id, options?)` | `POST /v1/memory/candidates/{id}/promote` | Promote to a real fact |
| `rejectCandidate(id, reason)` | `POST /v1/memory/candidates/{id}/reject` | Reject a candidate |
| `reviewContradictions(options?)` | `GET /v1/console/review/contradictions` | Live contradiction pass |
| `reviewQueue(options?)` | `GET /v1/console/review/queue` | Surfaced scheduler proposals |
| `applyExpiries(factIds)` | `POST /v1/console/review/expiries` | Apply reviewed expiries |
| `consolidate(request)` | `POST /v1/console/review/consolidations` | Atomic merge + signed receipt |
| `undoConsolidation(request)` | `POST /v1/console/review/consolidations/undo` | Reverse a consolidation |
| `localIngest(request)` | `POST /v1/local/ingest` | Ingest documents into a corpus |
| `importMemoryPack(request)` | `POST /v1/memory/import` | Import a signed `CruxPack` |
| `listExtensions()` | `GET /v1/extensions` | Installed extensions |
| `getExtension(id)` | `GET /v1/extensions/{id}` | One extension (`null` if absent) |
| `registerExtension(manifest)` | `POST /v1/extensions/register` | Register a signed manifest |
| `deleteExtension(id)` | `DELETE /v1/extensions/{id}` | Uninstall |
| `listRegistryEntries()` | `GET /v1/extensions/registry` | Curator-signed community index |
| `installFromRegistry(request)` | `POST /v1/extensions/install-from-registry` | Install from the index |
| `listTrustedKeys()` | `GET /v1/extensions/keys` | Trusted signing keys |
| `addTrustedKey(request)` | `POST /v1/extensions/keys` | Trust a key at a tier |
| `deleteTrustedKey(fpr)` | `DELETE /v1/extensions/keys/{fpr}` | Untrust a key |
| `listGrants(id)` | `GET /v1/extensions/{id}/grants` | Grants for an extension |
| `issueGrant(id, request)` | `POST /v1/extensions/{id}/grants` | Issue a capability grant |
| `revokeGrant(id, fpr)` | `DELETE /v1/extensions/{id}/grants/{fpr}` | Revoke a grant |
| `invokeExtensionTool(id, tool, options?)` | `POST /v1/extensions/{id}/tools/{tool}/invoke` | Dispatch a tool |
| `streamEvents(options?)` | `GET /v1/events/stream` | Event stream over `fetch` (recommended) |
| `subscribeEvents(options?)` | `GET /v1/events/stream` | Event stream via `EventSource` |

## Tests

```bash
npm test          # builds, then runs the wire-shape suite against a local stub
../live-smoke.sh  # runs every surface against a locally-started daemon
```

## API docs

Full HTTP API documentation is served by the daemon at `/v1/openapi.json`.

## Licence

Apache License, Version 2.0. See [LICENSE](../../LICENSE).
