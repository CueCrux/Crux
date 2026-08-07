# Crux framework adapters

Thin bindings that inject Crux memory into agent frameworks, over the daemon's
provider-neutral `GET /v1/context` surface.

| Framework | Status | Extra |
|---|---|---|
| LangChain | shipped | `pip install 'cuecrux-adapters[langchain]'` |
| LlamaIndex | planned (M6.3) | — |
| CrewAI | planned (M6.3) | — |

## The rule these adapters follow

**An adapter reshapes; it never re-decides.**

The daemon has already done the selection, the budget enforcement, the
supersession and the freshness classification. An adapter that re-ranks,
silently truncates, or hides a stale fact is not a thinner interface — it is a
different and worse memory, and it breaks the `stable_hash` guarantee that lets
provider-side prompt caches hit on the injected prefix.

That rule is not a convention here; it is [a test suite](#conformance). All
three adapters share one mapping ([`crux_adapters/core.py`](crux_adapters/core.py))
so a bug fixed once is fixed everywhere, and each framework binding is only the
translation into that framework's native types.

## Quick start

Requires a daemon with the context surface on (`CORECRUXD_CONTEXT_SURFACE=1` —
the routes 404 when it is off, deliberately, so a disabled surface cannot be
mistaken for an empty memory).

```python
from corecrux_client import CoreCruxClient
from crux_adapters.langchain import CruxContextRetriever, to_system_message
from crux_adapters.core import fetch_bundle

client = CoreCruxClient("http://127.0.0.1:14800")

# As a retriever, for any chain that takes one:
retriever = CruxContextRetriever(client=client, entity="project:atlas", token_budget=2000)
docs = retriever.invoke("what database do we use")

# Or as a system-message prefix, the injection shape:
message = to_system_message(fetch_bundle(client, entity="project:atlas"))
```

Runnable version, which boots its own daemon:

```bash
python examples/langchain_example.py --boot
```

**Scope your retrieval.** An unscoped bundle also carries the daemon's own
`__bootstrap__::` documentation facts, seeded on first boot and visible
whenever the caller is the operator. On a fresh daemon they outnumber your own
memory. Pass `entity=` or a `query`.

## Conformance

One suite, every adapter. Adding LlamaIndex and CrewAI in M6.3 means appending
two entries to `discover_adapters()` — if either needs a *new* case, that is a
signal worth recording in the ExecPlan, because the point is that one suite
covers all three.

```bash
python -m conformance                    # mapping + live (boots two daemons)
python -m conformance --mapping          # mapping only, no daemon needed
python -m unittest discover -s tests     # mapping layer + negative controls
```

Two layers, because they need different things:

**Mapping** — fixture bundles through the adapter. Pure, fast, no daemon, runs
in CI:

| Case | Property |
|---|---|
| `order-preserved` | Bundle order is kept exactly; no client-side sorting |
| `item-count` | Nothing added, nothing lost |
| `fact-text-format` | All adapters inject byte-identical text |
| `fact-metadata` | `entity` / `key` / `value` survive the mapping |
| `aux-item` | Non-fact sections keep id, text and kind |
| `stale-present` | A stale fact is **returned**, not filtered out |
| `stale-annotated` | …and carries `freshness: "stale"` |
| `truncation-surfaced` | A budget-truncated bundle says so |
| `section-kinds` | All five kinds map, in normative order |
| `empty-bundle` | An empty bundle is empty, not an error |

**Live** — a real daemon:

| Case | Property |
|---|---|
| `fidelity-membership` | Adapter items are exactly what `/v1/context` returned |
| `fidelity-order` | …in the daemon's fact order |
| `determinism-hash` | `stable_hash` identical across identical calls |
| `determinism-items` | …and so are the item ids and their order |
| `budget-passed-through` | `token_budget` reaches the daemon |
| `budget-respected` | `spent_est` never exceeds `min(requested, ceiling)` |
| `budget-truncation-reported` | A budget that cannot fit everything reports `dropped` |
| `superseded-absent` | A superseded version never appears |
| `superseded-id` | …and the live one does |
| `addressing` | `entity=` puts that entity first |
| `gated-off-404` | Surface disabled ⇒ a loud 404, never an empty bundle |

### Two deliberate choices

**Staleness is a mapping case, not a live one.** The daemon's shortest
configurable staleness horizon is one hour — `CORECRUXD_DECAY_VOLATILE_HOURS`
rejects values below 1 — so no live test can age a fact into staleness within a
run. Asserting it on a fixture is honest; asserting it live would mean sleeping
an hour or not really testing it.

**The suite is tested against non-conforming adapters.** It passed every real
adapter on its first run, which is exactly when a gate deserves suspicion.
[`tests/test_conformance.py`](tests/test_conformance.py) therefore includes six
negative controls — adapters that reorder, hide stale facts, strip metadata,
reformat text, drop a section kind, or invent items — and asserts the suite
catches each one. Loosen a case and one of those breaks.

## Layout

```
crux_adapters/core.py        framework-free mapping; the shared behaviour
crux_adapters/langchain.py   LangChain binding (Document, SystemMessage, BaseRetriever)
conformance/suite.py         the cases, and adapter discovery
conformance/daemon.py        throwaway corecruxd for the live layer
conformance/__main__.py      the runner; this is the gate
tests/test_conformance.py    mapping layer + negative controls (CI)
examples/langchain_example.py
```

## Licence

Apache License, Version 2.0. See [LICENSE](../../LICENSE).
