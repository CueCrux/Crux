# CueCrux Python Client

Python client for the [Crux Daemon](https://github.com/CueCrux/Crux) HTTP API.

Provides both synchronous and asynchronous interfaces using [httpx](https://www.python-httpx.org/).

## Installation

```bash
pip install cuecrux-client
```

Or install from source:

```bash
cd sdks/python
pip install -e .
```

## Quick start (sync)

```python
from cuecrux_client import CueCruxClient, StoreFact

with CueCruxClient("http://localhost:14800", token="my-token") as client:
    # Health check
    print(client.healthz())

    # Store a fact
    fact = client.store_fact(StoreFact(
        entity="user::alice",
        key="preferred_language",
        value="Python",
    ))
    print(fact.fact_id, fact.version)

    # Query facts
    result = client.query_facts("Python", top_k=5)
    for f in result.facts:
        print(f.entity, f.key, f.value)

    # Text search
    hits = client.text_search("my-tenant", "deployment guide")
    for h in hits.results:
        print(h.doc_id, h.score)
```

## Quick start (async)

```python
import asyncio
from cuecrux_client import AsyncCueCruxClient, StoreFact

async def main():
    async with AsyncCueCruxClient("http://localhost:14800", token="my-token") as client:
        fact = await client.store_fact(StoreFact(
            entity="user::alice",
            key="preferred_language",
            value="Python",
        ))
        print(fact.fact_id)

asyncio.run(main())
```

## Authentication

Pass a bearer token when constructing the client:

```python
client = CueCruxClient(token="my-bearer-token")
```

The token is sent as `Authorization: Bearer <token>` on every request.

## Error handling

All non-2xx responses raise `CueCruxError`:

```python
from cuecrux_client import CueCruxClient, CueCruxError

with CueCruxClient() as client:
    try:
        client.get_fact("nonexistent-id")
    except CueCruxError as e:
        print(e.status_code)  # 404
        print(e.detail)       # "fact 'nonexistent-id' not found"
```

Methods that naturally return "not found" (`get_fact`, `get_session`, `delete_fact`) return `None` or `False` instead of raising on 404.

## API coverage

| Endpoint | Sync | Async |
|---|---|---|
| `GET /healthz` | `healthz()` | `healthz()` |
| `GET /readyz` | `readyz()` | `readyz()` |
| `GET /v1/version` | `version()` | `version()` |
| `PUT /v1/facts` | `store_fact()` | `store_fact()` |
| `PUT /v1/facts/bulk` | `store_facts()` | `store_facts()` |
| `GET /v1/facts/{id}` | `get_fact()` | `get_fact()` |
| `DELETE /v1/facts/{id}` | `delete_fact()` | `delete_fact()` |
| `GET /v1/facts/entity/{e}` | `get_facts_by_entity()` | `get_facts_by_entity()` |
| `GET /v1/facts` | `query_facts()` | `query_facts()` |
| `GET /v1/facts/export` | `export_facts()` | `export_facts()` |
| `PUT /v1/sessions/{id}/state` | `put_session()` | `put_session()` |
| `GET /v1/sessions/{id}/state` | `get_session()` | `get_session()` |
| `POST /v1/query/text-search` | `text_search()` | `text_search()` |
| `POST /v1/query/text-search/expand` | `text_search_expand()` | `text_search_expand()` |
| `POST /v1/query/graph-expand` | `graph_expand()` | `graph_expand()` |
| `POST /v1/query/time-range` | `time_range()` | `time_range()` |
| `GET /v1/context` | `context()` | `context()` |
| `POST /v1/context` | `post_context()` | `post_context()` |
| `GET /v1/context?render=markdown` | `context_markdown()` | `context_markdown()` |
| `GET /v1/context?render=openai_messages` | `context_messages()` | `context_messages()` |
| `POST /v1/memory/extract` | `extract_memory()` | `extract_memory()` |
| `GET /v1/memory/candidates` | `list_candidates()` | `list_candidates()` |
| `POST /v1/memory/candidates/{id}/promote` | `promote_candidate()` | `promote_candidate()` |
| `POST /v1/memory/candidates/{id}/reject` | `reject_candidate()` | `reject_candidate()` |
| `GET /v1/console/review/contradictions` | `review_contradictions()` | `review_contradictions()` |
| `GET /v1/console/review/queue` | `review_queue()` | `review_queue()` |
| `POST /v1/console/review/expiries` | `apply_expiries()` | `apply_expiries()` |
| `POST /v1/console/review/consolidations` | `consolidate()` | `consolidate()` |
| `POST /v1/console/review/consolidations/undo` | `undo_consolidation()` | `undo_consolidation()` |
| `POST /v1/local/ingest` | `local_ingest()` | `local_ingest()` |
| `POST /v1/memory/import` | `import_memory_pack()` | `import_memory_pack()` |
| `GET /v1/extensions` | `list_extensions()` | `list_extensions()` |
| `GET /v1/extensions/{id}` | `get_extension()` | `get_extension()` |
| `POST /v1/extensions/register` | `register_extension()` | `register_extension()` |
| `DELETE /v1/extensions/{id}` | `delete_extension()` | `delete_extension()` |
| `GET /v1/extensions/registry` | `list_registry_entries()` | `list_registry_entries()` |
| `POST /v1/extensions/install-from-registry` | `install_from_registry()` | `install_from_registry()` |
| `GET /v1/extensions/keys` | `list_trusted_keys()` | `list_trusted_keys()` |
| `POST /v1/extensions/keys` | `add_trusted_key()` | `add_trusted_key()` |
| `DELETE /v1/extensions/keys/{fpr}` | `delete_trusted_key()` | `delete_trusted_key()` |
| `GET /v1/extensions/{id}/grants` | `list_grants()` | `list_grants()` |
| `POST /v1/extensions/{id}/grants` | `issue_grant()` | `issue_grant()` |
| `DELETE /v1/extensions/{id}/grants/{fpr}` | `revoke_grant()` | `revoke_grant()` |
| `POST /v1/extensions/{id}/tools/{tool}/invoke` | `invoke_extension_tool()` | `invoke_extension_tool()` |
| `GET /v1/events/stream` | `subscribe_events()` | `subscribe_events()` |

The async client mirrors the sync surface method-for-method; a test asserts the
two never drift apart.

## Context, review, consolidation and ingest

```python
# The provider-neutral injection bundle. Requires CORECRUXD_CONTEXT_SURFACE=1
# on the daemon (the route 404s when the surface is off).
bundle = client.context(entity="execplan:my-plan", token_budget=2000)
for section in bundle["sections"]:
    print(section["kind"], section["est_tokens"])

# stable_hash covers the ordered sections only, so it is byte-stable while the
# fact chain is unchanged -- that is what makes provider prompt caches hit.
print(bundle["stable_hash"])

markdown = client.context_markdown(entity="execplan:my-plan")

# Mine transcript text into review candidates. They land in a review namespace
# and never reach recall until promoted.
extracted = client.extract_memory(transcript)
client.promote_candidate(extracted["candidates"][0]["candidate_id"], reviewer="me")

# Merge duplicates atomically, with a signed diff receipt. Every target must
# live under the one (entity, key) being consolidated.
merged = client.consolidate("project", "status", "shipped", [a.fact_id, b.fact_id])
client.undo_consolidation(merged["receipt"]["canonical_fact_id"])

# Ingest documents; chunks without a dense_vector are embedded server-side.
client.local_ingest(
    "my-tenant", "notes",
    [{"doc_id": "d1", "chunks": [{"chunk_id": "c1", "text": "..."}]}],
)
```

## Events

`subscribe_events` yields decoded events as they arrive. The stream is infinite
-- `break` out of the loop to disconnect. Keep-alive comments are skipped.

```python
for event in client.subscribe_events(types=["fact.stored"]):
    print(event["type"], event["fact_id"])
    break

# The async client yields the same events:
async for event in aclient.subscribe_events(types=["fact.stored"]):
    ...
    break
```

## Tests

```bash
python -m unittest discover -s tests   # wire shape, against a local stub server
../live-smoke.sh                       # every surface, against a live daemon
```

## Requirements

- Python 3.10+
- httpx >= 0.27

## Licence

Apache License, Version 2.0. See [LICENSE](../../LICENSE).
