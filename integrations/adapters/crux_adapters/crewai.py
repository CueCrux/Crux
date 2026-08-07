# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.

"""CrewAI binding over ``GET /v1/context``.

Two shapes, both thin: a **tool** an agent can call to pull memory on demand,
and a **context string** for static injection into a Task description or an
Agent backstory.

Deliberately *not* a ``BaseKnowledgeSource``. That is CrewAI's obvious-looking
extension point, and it is the wrong one here: a knowledge source hands raw
content to CrewAI, which then chunks it, embeds it into its own vector store,
and retrieves against that store with its own ranking. Crux has already done
the selection, the budget enforcement and the ordering, and ``stable_hash``
covers exactly that ordering. Routing the bundle through a second retrieval
layer would discard all of it and re-decide what the agent sees -- the one
thing the conformance suite exists to prevent. A tool keeps Crux as the
retriever and CrewAI as the caller.

Install with the extra::

    pip install 'cuecrux-adapters[crewai]'
"""

from __future__ import annotations

from typing import Any

from .core import ContextBundle, ContextItem, fetch_bundle

__all__ = ["to_context_string", "CruxMemoryTool"]


def _require_crewai() -> None:
    try:
        import crewai  # noqa: F401
    except ModuleNotFoundError as err:  # pragma: no cover - import guard
        raise ModuleNotFoundError(
            "the CrewAI adapter needs crewai: pip install 'cuecrux-adapters[crewai]'"
        ) from err


def to_context_string(bundle: ContextBundle) -> str:
    """The bundle as one injectable block, in bundle order.

    Drop into a Task ``description`` or an Agent ``backstory``. Needs no CrewAI
    import -- it is just the bundle's text -- so it works before you have
    decided how to wire the crew.

    A truncated bundle says so in the header rather than presenting a partial
    memory as a whole one.
    """
    header = "Relevant memory from Crux:"
    if bundle.truncated:
        dropped = sum(int(d.get("count", 0)) for d in bundle.dropped)
        header = (
            f"Relevant memory from Crux "
            f"(truncated to fit the token budget; {dropped} item(s) omitted):"
        )
    return f"{header}\n{bundle.as_text()}"


def _build_tool_class() -> Any:
    """Define the tool lazily so importing this module never needs CrewAI."""
    _require_crewai()
    from crewai.tools import BaseTool

    class _CruxMemoryTool(BaseTool):
        """Let a CrewAI agent pull Crux memory on demand.

        Crux performs the recall; the agent's query is passed through to
        ``/v1/context``. The tool returns the bundle text in the daemon's
        order, unranked and unfiltered by this adapter.
        """

        name: str = "crux_memory"
        description: str = (
            "Recall durable project memory from Crux. "
            "Input: a short natural-language query describing what you need to remember."
        )

        client: Any = None
        entity: str | None = None
        session_id: str | None = None
        token_budget: int | None = None

        model_config = {"arbitrary_types_allowed": True}

        def _run(self, query: str = "", **_: Any) -> str:
            bundle = fetch_bundle(
                self.client,
                query=query or None,
                entity=self.entity,
                session_id=self.session_id,
                token_budget=self.token_budget,
            )
            return to_context_string(bundle)

    return _CruxMemoryTool


def CruxMemoryTool(**kwargs: Any) -> Any:  # noqa: N802 - class factory
    """Construct a Crux-backed CrewAI tool.

    A factory rather than a class so importing :mod:`crux_adapters` does not
    require CrewAI to be installed.
    """
    return _build_tool_class()(**kwargs)


def adapter_entrypoint(client: Any, **options: Any) -> ContextBundle:
    """Conformance hook: the bundle this adapter would inject."""
    return fetch_bundle(client, **options)


def adapter_items(bundle: ContextBundle) -> list[ContextItem]:
    """Conformance hook: the items this adapter presents, in its own order.

    The tool renders the whole bundle as one string, but it renders it from
    exactly these items in exactly this order, so the identity is the honest
    answer -- and it keeps CrewAI under the same order/fidelity cases as the
    other two adapters.
    """
    return list(bundle.items)
