# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.

"""LangChain binding over ``GET /v1/context``.

A thin wrapper, deliberately: :mod:`crux_adapters.core` does the mapping and
the daemon does the retrieval, so this module only translates neutral items
into LangChain's ``Document`` and message types. Anything here that filtered,
re-ranked or reformatted would put this adapter out of step with the
LlamaIndex and CrewAI bindings, which the conformance suite would then fail.

Install with the extra::

    pip install 'cuecrux-adapters[langchain]'
"""

from __future__ import annotations

from typing import Any

from .core import ContextBundle, ContextItem, fetch_bundle

__all__ = ["to_documents", "to_system_message", "CruxContextRetriever"]


def _require_langchain() -> Any:
    try:
        import langchain_core  # noqa: F401
    except ModuleNotFoundError as err:  # pragma: no cover - import guard
        raise ModuleNotFoundError(
            "the LangChain adapter needs langchain-core: "
            "pip install 'cuecrux-adapters[langchain]'"
        ) from err
    return langchain_core


def to_documents(bundle: ContextBundle) -> list[Any]:
    """Bundle items as LangChain ``Document``s, in bundle order.

    Order is the daemon's presentation order -- facts by ``(entity, key,
    fact_id)``, sections in normative order -- and is preserved exactly. It is
    not a relevance ranking and must not be re-sorted: the ordering is what
    ``stable_hash`` covers, so reordering breaks prompt-cache hits.

    Each document's metadata carries ``crux_id``, ``crux_kind`` and the item's
    daemon metadata, including ``freshness``. A ``freshness == "stale"``
    document is still returned -- the daemon annotates staleness rather than
    hiding it, and so does this adapter.
    """
    _require_langchain()
    from langchain_core.documents import Document

    return [
        Document(
            page_content=item.text,
            metadata={"crux_id": item.id, "crux_kind": item.kind, **item.metadata},
        )
        for item in bundle.items
    ]


def to_system_message(bundle: ContextBundle) -> Any:
    """The whole bundle as one ``SystemMessage`` -- the injection-prefix shape.

    Prefer this over :func:`to_documents` when you want the bundle as a
    conversational prefix rather than as retrieved chunks.
    """
    _require_langchain()
    from langchain_core.messages import SystemMessage

    return SystemMessage(
        content=bundle.as_text(),
        additional_kwargs={
            "crux_stable_hash": bundle.stable_hash,
            "crux_bundle_version": bundle.bundle_version,
            "crux_truncated": bundle.truncated,
        },
    )


def _build_retriever_class() -> Any:
    """Define the retriever lazily so importing this module never needs LangChain."""
    _require_langchain()
    from langchain_core.callbacks import CallbackManagerForRetrieverRun
    from langchain_core.documents import Document
    from langchain_core.retrievers import BaseRetriever

    class _CruxContextRetriever(BaseRetriever):
        """Retrieve Crux memory as LangChain ``Document``s.

        The daemon performs the recall; ``query`` is passed through to
        ``/v1/context`` rather than being matched client-side.
        """

        client: Any
        """A ``corecrux_client.CoreCruxClient``."""

        entity: str | None = None
        """Typed address resolved first, e.g. ``execplan:<slug>``."""

        session_id: str | None = None
        token_budget: int | None = None

        model_config = {"arbitrary_types_allowed": True}

        def _get_relevant_documents(
            self, query: str, *, run_manager: CallbackManagerForRetrieverRun | None = None
        ) -> list[Document]:
            bundle = fetch_bundle(
                self.client,
                query=query or None,
                entity=self.entity,
                session_id=self.session_id,
                token_budget=self.token_budget,
            )
            return to_documents(bundle)

    return _CruxContextRetriever


def CruxContextRetriever(**kwargs: Any) -> Any:  # noqa: N802 - it is a class factory
    """Construct a Crux-backed LangChain retriever.

    A factory rather than a class so that importing :mod:`crux_adapters` does
    not require LangChain to be installed -- the conformance suite imports the
    package with no frameworks present.
    """
    return _build_retriever_class()(**kwargs)


def adapter_entrypoint(client: Any, **options: Any) -> ContextBundle:
    """Conformance hook: return the bundle this adapter would inject.

    Every adapter exposes this so ``conformance/suite.py`` can compare all of
    them against raw ``/v1/context`` through one code path.
    """
    return fetch_bundle(client, **options)


def adapter_items(bundle: ContextBundle) -> list[ContextItem]:
    """Conformance hook: the items this adapter presents, in its own order.

    LangChain documents map 1:1 onto bundle items, so this is the identity --
    stated explicitly rather than assumed, because that is exactly the property
    the suite is checking.
    """
    return list(bundle.items)
