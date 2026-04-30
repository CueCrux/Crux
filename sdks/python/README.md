# CoreCrux Python Client

Python client for the [Crux Daemon](https://github.com/CueCrux/Crux) HTTP API.

Provides both synchronous and asynchronous interfaces using [httpx](https://www.python-httpx.org/).

## Installation

```bash
pip install corecrux-client
```

Or install from source:

```bash
cd sdks/python
pip install -e .
```

## Quick start (sync)

```python
from corecrux_client import CoreCruxClient, StoreFact

with CoreCruxClient("http://localhost:14800", token="my-token") as client:
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
from corecrux_client import AsyncCoreCruxClient, StoreFact

async def main():
    async with AsyncCoreCruxClient("http://localhost:14800", token="my-token") as client:
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
client = CoreCruxClient(token="my-bearer-token")
```

The token is sent as `Authorization: Bearer <token>` on every request.

## Error handling

All non-2xx responses raise `CoreCruxError`:

```python
from corecrux_client import CoreCruxClient, CoreCruxError

with CoreCruxClient() as client:
    try:
        client.get_fact("nonexistent-id")
    except CoreCruxError as e:
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

## Requirements

- Python 3.10+
- httpx >= 0.27

## Licence

CueCrux Community Licence (CCL v1.0). See [LICENCE.md](../../LICENCE.md).
