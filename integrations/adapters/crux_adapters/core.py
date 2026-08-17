# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.

"""Framework-free mapping from a ``context_bundle/v1`` to neutral items.

Every adapter in this package is a thin binding over this module. Keeping the
mapping here rather than in each framework binding is what makes one
conformance suite meaningful: LangChain, LlamaIndex and CrewAI all present the
*same* items in the *same* order, and a bug fixed once is fixed everywhere.

The daemon owns the hard parts -- selection, budget enforcement, supersession,
freshness classification -- and this module deliberately re-does none of them.
It reshapes; it never filters, reorders or re-ranks. See
``conformance/suite.py`` for the properties that pins down.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "ContextItem",
    "ContextBundle",
    "SECTION_KINDS",
    "bundle_from_json",
    "fetch_bundle",
    "format_fact",
]

#: Section kinds in the daemon's normative order (spec sections 2 and 4).
#: Adapters must preserve this order; they must not sort by score.
SECTION_KINDS = ("facts", "dossier", "session_state", "work_table", "coord")


def format_fact(entity: str, key: str, value: str) -> str:
    """Render one fact as a single injectable line.

    Defined once, here, so all three adapters inject byte-identical text. A
    framework binding that reformats this breaks cross-adapter comparability
    for no gain.
    """
    return f"{entity} · {key}: {value}"


@dataclass(frozen=True)
class ContextItem:
    """One injectable unit from the bundle, in bundle order."""

    id: str
    """``fact_id`` for a fact, or the aux item's ``id``. Stable across calls."""

    text: str
    """The injectable line. For facts, :func:`format_fact`; else the raw text."""

    kind: str
    """Section kind this item came from -- one of :data:`SECTION_KINDS`."""

    metadata: dict[str, Any] = field(default_factory=dict)
    """Everything the daemon said about the item. For facts this carries
    ``entity``, ``key``, ``value``, ``confidence``, ``horizon_class``,
    ``freshness`` and ``est_tokens``. ``freshness == "stale"`` is an
    annotation, never a reason to drop the item -- the daemon already decided
    it was worth injecting."""


@dataclass(frozen=True)
class ContextBundle:
    """A ``context_bundle/v1`` reshaped into ordered, framework-neutral items."""

    items: tuple[ContextItem, ...]
    bundle_version: str
    stable_hash: str
    """``blake3:<hex>`` over the stable region only. Byte-stable across calls
    while the fact chain is unchanged, which is what lets provider-side prompt
    caches hit on the injected prefix."""
    budget: dict[str, Any]
    dropped: tuple[dict[str, Any], ...]
    """Items the budget excluded. Non-empty means the bundle is truncated;
    an adapter must surface this rather than present a short bundle as whole."""
    session_id: str | None
    assembled_at: str
    receipt_ref: str | None
    raw: dict[str, Any]
    """The untouched response, so a caller is never worse off for going
    through an adapter."""

    @property
    def truncated(self) -> bool:
        """True when the budget forced anything out of the bundle."""
        return bool(self.dropped)

    def as_text(self, separator: str = "\n") -> str:
        """All item text joined in bundle order -- the injectable prefix."""
        return separator.join(item.text for item in self.items)


def bundle_from_json(payload: dict[str, Any]) -> ContextBundle:
    """Reshape a ``GET/POST /v1/context`` JSON body.

    Pure: no I/O, no clock, no network. The conformance suite drives this
    directly with fixture bundles so the mapping properties can be asserted
    without a daemon.
    """
    items: list[ContextItem] = []

    for section in payload.get("sections") or ():
        kind = section.get("kind", "")
        # Facts and aux items are mutually exclusive per section, but iterate
        # both rather than branching on kind: a future section kind carrying
        # facts would otherwise be silently dropped.
        for fact in section.get("facts") or ():
            items.append(
                ContextItem(
                    id=fact["fact_id"],
                    text=format_fact(fact["entity"], fact["key"], fact["value"]),
                    kind=kind,
                    metadata={
                        "entity": fact["entity"],
                        "key": fact["key"],
                        "value": fact["value"],
                        "confidence": fact.get("confidence"),
                        "horizon_class": fact.get("horizon_class"),
                        "freshness": fact.get("freshness"),
                        "est_tokens": fact.get("est_tokens"),
                        "section": kind,
                    },
                )
            )
        for aux in section.get("items") or ():
            items.append(
                ContextItem(
                    id=aux["id"],
                    text=aux.get("text", ""),
                    kind=kind,
                    metadata={"est_tokens": aux.get("est_tokens"), "section": kind},
                )
            )

    budget = payload.get("budget") or {}
    return ContextBundle(
        items=tuple(items),
        bundle_version=payload.get("bundle_version", ""),
        stable_hash=payload.get("stable_hash", ""),
        budget=budget,
        dropped=tuple(budget.get("dropped") or ()),
        session_id=payload.get("session_id"),
        assembled_at=payload.get("assembled_at", ""),
        receipt_ref=payload.get("receipt_ref"),
        raw=payload,
    )


def fetch_bundle(
    client: Any,
    *,
    session_id: str | None = None,
    entity: str | None = None,
    query: str | None = None,
    token_budget: int | None = None,
) -> ContextBundle:
    """Fetch and reshape a bundle using a ``cuecrux_client`` instance.

    ``client`` is a ``CueCruxClient`` (or anything with a compatible
    ``context()``), so adapters inherit the SDK's auth, timeouts and error
    types instead of re-implementing them.

    Raises ``CueCruxError`` with status 404 when the daemon's context surface
    is disabled (``CORECRUXD_CONTEXT_SURFACE`` unset) -- a loud failure, not an
    empty bundle, so a misconfigured daemon cannot look like an empty memory.
    """
    payload = client.context(
        session_id=session_id, entity=entity, query=query, token_budget=token_budget
    )
    return bundle_from_json(payload)
