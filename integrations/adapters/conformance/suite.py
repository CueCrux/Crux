# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.

"""The adapter conformance suite. One suite, every adapter.

An adapter's whole job is to present ``GET /v1/context`` in a framework's
native shape **without changing what it says**. The daemon has already done
the selection, the budget enforcement, the supersession and the freshness
classification; an adapter that re-ranks, silently truncates, or hides a stale
fact is not a thinner interface, it is a different and worse memory. These
cases pin that down.

Two layers, because they need different things:

* **Mapping** -- drives fixture bundles through the adapter. Pure, fast, needs
  no daemon, runs in CI. Covers the properties that are about *reshaping*.
* **Live** -- drives a real daemon. Covers the properties that are about the
  round trip: determinism of ``stable_hash``, budget pass-through, supersession
  and the disabled-surface failure mode.

Staleness annotation is a mapping case rather than a live one on purpose: the
daemon's shortest configurable staleness horizon is one hour
(``CORECRUXD_DECAY_VOLATILE_HOURS`` rejects values below 1), so no live test
can age a fact into staleness within a run. Asserting it on a fixture is honest;
asserting it live would mean either sleeping an hour or not really testing it.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "sdks" / "python" / "src"))

from crux_adapters.core import (  # noqa: E402
    SECTION_KINDS,
    ContextBundle,
    ContextItem,
    bundle_from_json,
    format_fact,
)

__all__ = [
    "Adapter",
    "Failure",
    "discover_adapters",
    "run_mapping_cases",
    "run_live_cases",
    "FIXTURES",
]


@dataclass(frozen=True)
class Adapter:
    """What the suite needs from any adapter, framework-agnostic."""

    name: str
    fetch: Callable[..., ContextBundle]
    """``(client, **options) -> ContextBundle`` -- what this adapter injects."""
    items: Callable[[ContextBundle], list[ContextItem]]
    """The items the adapter presents, in the order it presents them."""


@dataclass(frozen=True)
class Failure:
    adapter: str
    case: str
    detail: str

    def __str__(self) -> str:
        return f"{self.adapter}/{self.case}: {self.detail}"


# ── Adapter discovery ────────────────────────────────────────────────────
#
# M6.3 adds LlamaIndex and CrewAI by appending two entries here. If a new
# adapter needs a new case, that is a signal worth recording in the plan --
# the whole point is that one suite covers all three.


#: ``(adapter name, module, guard callable)``. A binding joins the suite by
#: appending one row. That is the whole registration cost, and it is the
#: property M6.3 was meant to demonstrate: LlamaIndex and CrewAI were added
#: here without changing a single case.
_BINDINGS = (
    ("langchain", "crux_adapters.langchain", "_require_langchain"),
    ("llamaindex", "crux_adapters.llamaindex", "_require_llamaindex"),
    ("crewai", "crux_adapters.crewai", "_require_crewai"),
)


def discover_adapters() -> list[Adapter]:
    """Every adapter whose framework is importable, plus the neutral core.

    The core entry always runs, so the mapping properties are covered even on
    a machine with no frameworks installed.
    """
    import importlib

    from crux_adapters import core

    adapters = [
        Adapter(name="core", fetch=core.fetch_bundle, items=lambda b: list(b.items)),
    ]

    for name, module_name, guard in _BINDINGS:
        try:
            module = importlib.import_module(module_name)
            getattr(module, guard)()
        except ModuleNotFoundError:
            # Framework not installed: skip, so the suite runs anywhere. CI
            # installs all three, and asserts the full set is discovered.
            continue
        adapters.append(
            Adapter(name=name, fetch=module.adapter_entrypoint, items=module.adapter_items)
        )

    return adapters


# ── Fixtures for the mapping layer ───────────────────────────────────────


def _fact(fact_id: str, entity: str, key: str, value: str, **over: Any) -> dict[str, Any]:
    return {
        "fact_id": fact_id,
        "entity": entity,
        "key": key,
        "value": value,
        "confidence": 1.0,
        "horizon_class": "stable",
        "freshness": "fresh",
        "est_tokens": 12,
        **over,
    }


FIXTURES: dict[str, dict[str, Any]] = {
    # Facts already in the daemon's presentation order: (entity, key, fact_id).
    "ordered": {
        "bundle_version": "context_bundle/v1",
        "stable_hash": "blake3:aaaa",
        "assembled_at": "2026-08-07T00:00:00Z",
        "session_id": None,
        "receipt_ref": "r_1",
        "budget": {"requested": 2000, "ceiling": 8000, "spent_est": 36},
        "sections": [
            {
                "kind": "facts",
                "est_tokens": 36,
                "facts": [
                    _fact("f_1", "alpha", "k1", "v1"),
                    _fact("f_2", "alpha", "k2", "v2"),
                    _fact("f_3", "beta", "k1", "v3"),
                ],
            },
            {
                "kind": "session_state",
                "est_tokens": 9,
                "items": [{"id": "s_1", "text": "resume here", "est_tokens": 9}],
            },
        ],
    },
    # A stale fact is annotated, never withheld.
    "stale": {
        "bundle_version": "context_bundle/v1",
        "stable_hash": "blake3:bbbb",
        "assembled_at": "2026-08-07T00:00:00Z",
        "budget": {"requested": 2000, "ceiling": 8000, "spent_est": 24},
        "sections": [
            {
                "kind": "facts",
                "est_tokens": 24,
                "facts": [
                    _fact("f_fresh", "alpha", "k1", "current", freshness="fresh"),
                    _fact(
                        "f_stale",
                        "alpha",
                        "k2",
                        "aging",
                        freshness="stale",
                        horizon_class="volatile",
                    ),
                ],
            }
        ],
    },
    # The budget forced items out: truncation must be visible.
    "truncated": {
        "bundle_version": "context_bundle/v1",
        "stable_hash": "blake3:cccc",
        "assembled_at": "2026-08-07T00:00:00Z",
        "budget": {
            "requested": 20,
            "ceiling": 8000,
            "spent_est": 12,
            "dropped": [{"kind": "facts", "count": 4, "reason": "budget"}],
        },
        "sections": [
            {"kind": "facts", "est_tokens": 12, "facts": [_fact("f_1", "alpha", "k1", "v1")]}
        ],
    },
    # Every section kind at once, in normative order.
    "all_kinds": {
        "bundle_version": "context_bundle/v1",
        "stable_hash": "blake3:dddd",
        "assembled_at": "2026-08-07T00:00:00Z",
        "budget": {"requested": 2000, "ceiling": 8000, "spent_est": 50},
        "sections": [
            {"kind": "facts", "est_tokens": 12, "facts": [_fact("f_1", "a", "k", "v")]},
            {"kind": "dossier", "est_tokens": 9, "items": [{"id": "d_1", "text": "dossier"}]},
            {"kind": "session_state", "est_tokens": 9, "items": [{"id": "s_1", "text": "state"}]},
            {"kind": "work_table", "est_tokens": 9, "items": [{"id": "w_1", "text": "work"}]},
            {"kind": "coord", "est_tokens": 9, "items": [{"id": "c_1", "text": "coord"}]},
        ],
    },
    "empty": {
        "bundle_version": "context_bundle/v1",
        "stable_hash": "blake3:eeee",
        "assembled_at": "2026-08-07T00:00:00Z",
        "budget": {"requested": 2000, "ceiling": 8000, "spent_est": 0},
        "sections": [],
    },
}


# ── Mapping cases ────────────────────────────────────────────────────────


def run_mapping_cases(adapter: Adapter) -> list[Failure]:
    """Properties about reshaping a bundle. No daemon, no network."""
    out: list[Failure] = []

    def check(case: str, ok: bool, detail: str) -> None:
        if not ok:
            out.append(Failure(adapter.name, case, detail))

    # 1. Bundle order is preserved exactly -- an adapter must not re-sort.
    bundle = bundle_from_json(FIXTURES["ordered"])
    ids = [i.id for i in adapter.items(bundle)]
    check(
        "order-preserved",
        ids == ["f_1", "f_2", "f_3", "s_1"],
        f"expected bundle order ['f_1','f_2','f_3','s_1'], got {ids}",
    )

    # 2. Nothing is added or lost.
    check(
        "item-count",
        len(ids) == 4,
        f"expected 4 items across 2 sections, got {len(ids)}",
    )

    # 3. Fact text uses the one shared rendering, and the parts survive.
    items = adapter.items(bundle)
    first = items[0]
    check(
        "fact-text-format",
        first.text == format_fact("alpha", "k1", "v1"),
        f"fact text is {first.text!r}, expected {format_fact('alpha', 'k1', 'v1')!r}",
    )
    check(
        "fact-metadata",
        first.metadata.get("entity") == "alpha"
        and first.metadata.get("key") == "k1"
        and first.metadata.get("value") == "v1",
        f"entity/key/value missing from metadata: {first.metadata}",
    )

    # 4. Aux items keep their id and text.
    aux = items[-1]
    check(
        "aux-item",
        aux.id == "s_1" and aux.text == "resume here" and aux.kind == "session_state",
        f"aux item mapped as id={aux.id!r} text={aux.text!r} kind={aux.kind!r}",
    )

    # 5. A stale fact is PRESENT and annotated. Hiding it would silently
    #    change what the daemon decided to inject.
    stale = bundle_from_json(FIXTURES["stale"])
    stale_items = {i.id: i for i in adapter.items(stale)}
    check(
        "stale-present",
        "f_stale" in stale_items,
        "a fact with freshness='stale' was dropped; it must be annotated, not withheld",
    )
    if "f_stale" in stale_items:
        check(
            "stale-annotated",
            stale_items["f_stale"].metadata.get("freshness") == "stale",
            f"freshness not surfaced: {stale_items['f_stale'].metadata}",
        )

    # 6. Truncation is visible rather than presented as a whole bundle.
    truncated = bundle_from_json(FIXTURES["truncated"])
    check(
        "truncation-surfaced",
        truncated.truncated and truncated.dropped[0]["count"] == 4,
        f"dropped not surfaced: truncated={truncated.truncated} dropped={truncated.dropped}",
    )

    # 7. Every section kind maps, in normative order.
    all_kinds = bundle_from_json(FIXTURES["all_kinds"])
    kinds = [i.kind for i in adapter.items(all_kinds)]
    check(
        "section-kinds",
        kinds == list(SECTION_KINDS),
        f"expected sections in normative order {list(SECTION_KINDS)}, got {kinds}",
    )

    # 8. An empty bundle is empty, not an error.
    empty = bundle_from_json(FIXTURES["empty"])
    check("empty-bundle", adapter.items(empty) == [], "an empty bundle produced items")

    return out


# ── Live cases ───────────────────────────────────────────────────────────


def run_live_cases(
    adapter: Adapter, client: Any, *, gated_off_client: Any | None = None
) -> list[Failure]:
    """Properties about the round trip. Needs a daemon with the context
    surface ON, and optionally a second one with it OFF for the 404 case."""
    from cuecrux_client.errors import CueCruxError
    from cuecrux_client.types import StoreFact

    out: list[Failure] = []

    def check(case: str, ok: bool, detail: str) -> None:
        if not ok:
            out.append(Failure(adapter.name, case, detail))

    prefix = f"conf-{adapter.name}"
    client.store_fact(StoreFact(entity=f"{prefix}:one", key="k", value="first"))
    client.store_fact(StoreFact(entity=f"{prefix}:two", key="k", value="second"))

    # 1. The adapter presents exactly what /v1/context returned, in order.
    raw = client.context(token_budget=4000)
    expected = [
        f["fact_id"] for s in raw.get("sections", []) for f in (s.get("facts") or ())
    ] + [i["id"] for s in raw.get("sections", []) for i in (s.get("items") or ())]
    bundle = adapter.fetch(client, token_budget=4000)
    got = [i.id for i in adapter.items(bundle)]
    # Compare as sets for membership and as lists for the facts' relative
    # order; aux items follow their own section, so a strict list compare
    # across kinds would over-specify.
    check(
        "fidelity-membership",
        set(got) == set(expected),
        f"adapter items differ from raw /v1/context: only-adapter={set(got) - set(expected)} "
        f"only-raw={set(expected) - set(got)}",
    )
    raw_facts = [f["fact_id"] for s in raw.get("sections", []) for f in (s.get("facts") or ())]
    got_facts = [i.id for i in adapter.items(bundle) if i.kind == "facts"]
    check(
        "fidelity-order",
        got_facts == raw_facts,
        f"adapter reordered facts: {got_facts} vs raw {raw_facts}",
    )

    # 2. The stable region is byte-stable across identical calls. This is what
    #    makes provider-side prompt caches hit; an adapter that reassembles
    #    the bundle itself would break it.
    again = adapter.fetch(client, token_budget=4000)
    check(
        "determinism-hash",
        again.stable_hash == bundle.stable_hash and bundle.stable_hash != "",
        f"stable_hash changed across identical calls: {bundle.stable_hash} -> {again.stable_hash}",
    )
    check(
        "determinism-items",
        [i.id for i in adapter.items(again)] == got,
        "item ids/order changed across identical calls",
    )

    # 3. The token budget is passed through and respected.
    budgeted = adapter.fetch(client, token_budget=1)
    spent = budgeted.budget.get("spent_est", 0)
    requested = budgeted.budget.get("requested")
    ceiling = budgeted.budget.get("ceiling", 0)
    check(
        "budget-passed-through",
        requested == 1,
        f"token_budget=1 did not reach the daemon; budget.requested={requested}",
    )
    check(
        "budget-respected",
        spent <= min(1, ceiling),
        f"spent_est {spent} exceeds the effective budget {min(1, ceiling)}",
    )

    # 4. A budget that cannot fit everything reports the truncation.
    check(
        "budget-truncation-reported",
        budgeted.truncated,
        "a 1-token budget dropped items but `dropped` was empty",
    )

    # 5. A superseded fact never appears. Writing the same (entity, key)
    #    twice supersedes v1; only the live version may be injected.
    client.store_fact(StoreFact(entity=f"{prefix}:super", key="k", value="v1"))
    v2 = client.store_fact(StoreFact(entity=f"{prefix}:super", key="k", value="v2"))
    supers = adapter.fetch(client, entity=f"{prefix}:super", token_budget=4000)
    values = [i.metadata.get("value") for i in adapter.items(supers)]
    check(
        "superseded-absent",
        "v1" not in values and "v2" in values,
        f"expected only the live version; got {values}",
    )
    check(
        "superseded-id",
        any(i.id == v2.fact_id for i in adapter.items(supers)),
        f"the live fact {v2.fact_id} is missing from the bundle",
    )

    # 6. Addressed recall puts the named entity first (spec section 4 rule 1).
    addressed = adapter.fetch(client, entity=f"{prefix}:two", token_budget=4000)
    addressed_items = [i for i in adapter.items(addressed) if i.kind == "facts"]
    check(
        "addressing",
        bool(addressed_items) and addressed_items[0].metadata.get("entity") == f"{prefix}:two",
        f"addressed entity is not first: "
        f"{[i.metadata.get('entity') for i in addressed_items][:3]}",
    )

    # 7. With the surface disabled the adapter fails loudly. An empty bundle
    #    here would make a misconfigured daemon look like an empty memory.
    if gated_off_client is not None:
        try:
            adapter.fetch(gated_off_client, token_budget=500)
        except CueCruxError as err:
            check(
                "gated-off-404",
                err.status_code == 404,
                f"expected HTTP 404 when CORECRUXD_CONTEXT_SURFACE is off, got {err.status_code}",
            )
        except Exception as err:  # noqa: BLE001
            out.append(
                Failure(adapter.name, "gated-off-404", f"expected CueCruxError, got {err!r}")
            )
        else:
            out.append(
                Failure(
                    adapter.name,
                    "gated-off-404",
                    "returned a bundle while the context surface was disabled",
                )
            )

    return out
