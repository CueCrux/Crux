# Crux framework adapters

Thin bindings that inject Crux memory into agent frameworks, over the daemon's
provider-neutral `GET /v1/context` surface.

| Framework | Native shape | Extra |
|---|---|---|
| LangChain | `Document`, `SystemMessage`, `BaseRetriever` | `pip install 'cuecrux-adapters[langchain]'` |
| LlamaIndex | `NodeWithScore`, `BaseRetriever` | `pip install 'cuecrux-adapters[llamaindex]'` |
| CrewAI | `BaseTool`, context string | `pip install 'cuecrux-adapters[crewai]'` |

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
from cuecrux_client import CueCruxClient
from crux_adapters.langchain import CruxContextRetriever, to_system_message
from crux_adapters.core import fetch_bundle

client = CueCruxClient("http://127.0.0.1:14800")

# As a retriever, for any chain that takes one:
retriever = CruxContextRetriever(client=client, entity="project:atlas", token_budget=2000)
docs = retriever.invoke("what database do we use")

# Or as a system-message prefix, the injection shape:
message = to_system_message(fetch_bundle(client, entity="project:atlas"))
```

LlamaIndex and CrewAI, same bundle, native shapes:

```python
from crux_adapters.llamaindex import CruxContextRetriever as LlamaRetriever
from crux_adapters.crewai import CruxMemoryTool

nodes = LlamaRetriever(client, entity="project:atlas").retrieve("what database")
tool = CruxMemoryTool(client=client, entity="project:atlas")   # attach to any Agent
```

Runnable versions, which boot their own daemon:

```bash
python examples/langchain_example.py --boot
python examples/crewai_example.py --boot
```

### Scoping: `entity` filters, `query` does not

Measured against a fresh daemon holding exactly one user fact
(`project:atlas · database`), plus the `__bootstrap__::` documentation facts
the daemon seeds on first boot:

| Call | Facts returned | Of them, yours |
|---|---|---|
| no arguments | 20 | 1 |
| `entity="project:atlas"` | 1 | 1 |
| `query="what database does atlas use"` | 31 | 0 |
| both | 32 | 1 |

Two things follow, and both are easy to get wrong:

- **`entity=` is the only true scope.** It resolves that entity first *and*
  restricts to it.
- **`query=` is a union, not a filter.** It *adds* keyword recall on top, so
  `entity=` plus `query=` returns more than `entity=` alone, not less.

The bootstrap facts are visible whenever the caller is the operator (auth off,
or an operator passport), and on a fresh daemon they dominate keyword recall —
in the probe above a natural-language query returned 31 facts, none of them the
user's own. Pass `entity=` when you want scoped recall. This is daemon-side
ranking behaviour, not something the adapters filter: an adapter that dropped
results here would be re-deciding, which is exactly what the suite forbids.

## Conformance

One suite, every adapter. Adding LlamaIndex and CrewAI took **one row each in
`_BINDINGS`** and changed no case — which was the point of writing the suite
before the second and third adapters existed.

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

## Jev decision receipts

[Jev](https://docs.typesafe.ai/) answers typed questions (Choice / Score /
Noul) about a `state` and keeps nothing. `crux_adapters.jev.decide` gives each
call a record: Crux builds the state, Jev answers, the daemon signs a
`model_invocation` receipt, and the decision is stored as a fact linked to that
receipt. Needs `CORECRUXD_STREAM_RECEIPTS=1` and `CORECRUXD_CONTEXT_SURFACE=1`.
Setup, a runnable guardrail example and receipt verification are in the
[Jev decision receipts cookbook](../../docs/jev-decision-receipts.md).

```python
from crux_adapters.jev import decide

decision = decide(
    client,
    {"block": {"type": "noul", "instructions": "Should this command be blocked?"}},
    entity="invoice:42",                 # retrieval scope + decision memory jev:invoice:42
    token_budget=1000,                   # mandatory: bounds the retrieved context
    untrusted={"tool_output": output},   # never mixed into trusted_context
)                                        # Jev key: TYPESAFE_API_KEY, or pass jev=
decision.answers["block"]["noul"], decision.receipt_id, decision.request_id
```

- **State**: `trusted_context` is the bundle text, in bundle order;
  `untrusted_input` is whatever the caller passed, verbatim. Separating them
  does not by itself make Jev resist injection. It makes the split visible
  and hashed, so it can be measured.
- **Receipt**: `prompt_hash` covers `{state, questions}`, `retrieval_set_hash`
  covers the evidence (`[id, digest(text)]` per item) and `output_hash` covers
  `{model, answers}`. Each is sha256 over compact JSON with key order
  preserved, because Jev reads key order too: reordering a Choice's options
  changes the prompt. The exact serialiser is in the cookbook's
  [Canonical hashing](../../docs/jev-decision-receipts.md#canonical-hashing).
- **Fact**: `jev:<entity>` / `decision:<request_id>`, with `source_receipt`.
  The value holds the answers and the evidence list, so both hashes can be
  recomputed from the fact alone and checked against the signed receipt.
- **Failures are loud.** If the receipt or the fact is not written, the call
  raises `DecisionNotRecorded`, and `.decision` still holds the answers.

A receipt shows what was asked, of which model version, on what evidence, and
what came back, **as the calling process reported it**: the daemon never talks
to Jev, it signs the hashes it is sent, so it vouches for when and by whom a
decision was recorded, not that Jev produced it (`provider_request_id` is what
reconciles a receipt with TypeSafe's own logs). It does not show that the
decision was right.

## Layout

```
crux_adapters/core.py        framework-free mapping; the shared behaviour
crux_adapters/langchain.py   LangChain binding (Document, SystemMessage, BaseRetriever)
crux_adapters/llamaindex.py  LlamaIndex binding (NodeWithScore, BaseRetriever)
crux_adapters/crewai.py      CrewAI binding (BaseTool, context string)
crux_adapters/jev.py         Jev decision receipts (state, receipt, decision fact)
conformance/suite.py         the cases, and adapter discovery
conformance/daemon.py        throwaway corecruxd for the live layer
conformance/__main__.py      the runner; this is the gate
tests/test_conformance.py    mapping layer + negative controls (CI)
tests/test_jev.py            Jev wrapper over mocked HTTP (CI); opt-in live layers
examples/langchain_example.py
examples/crewai_example.py
```

## Two framework-shape decisions worth knowing

**LlamaIndex nodes carry `score=None`.** Bundle order is the daemon's
*presentation* order, not a relevance ranking. Filling in a synthetic
descending score would let downstream LlamaIndex components re-sort or
threshold on a number this adapter invented — the re-deciding the suite
forbids.

**CrewAI gets a tool, not a `BaseKnowledgeSource`.** The knowledge-source
extension point looks like the obvious fit and is the wrong one: it hands raw
content to CrewAI, which chunks it, embeds it into its own vector store, and
retrieves against that store with its own ranking. Crux has already done the
selection, the budget enforcement and the ordering, and `stable_hash` covers
exactly that ordering. Routing the bundle through a second retrieval layer
would discard all of it. A tool keeps Crux as the retriever and CrewAI as the
caller.

## Licence

Apache License, Version 2.0. See [LICENSE](../../LICENSE).
