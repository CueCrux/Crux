# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.

"""LlamaIndex binding over ``GET /v1/context``.

Thin, like the LangChain binding: :mod:`crux_adapters.core` does the mapping
and the daemon does the retrieval, so this module only translates neutral
items into LlamaIndex's node types. It passes the same conformance suite,
unmodified.

Install with the extra::

    pip install 'cuecrux-adapters[llamaindex]'
"""

from __future__ import annotations

from typing import Any

from .core import ContextBundle, ContextItem, fetch_bundle

__all__ = ["to_nodes", "CruxContextRetriever"]


def _require_llamaindex() -> None:
    try:
        import llama_index.core  # noqa: F401
    except ModuleNotFoundError as err:  # pragma: no cover - import guard
        raise ModuleNotFoundError(
            "the LlamaIndex adapter needs llama-index-core: "
            "pip install 'cuecrux-adapters[llamaindex]'"
        ) from err


def to_nodes(bundle: ContextBundle) -> list[Any]:
    """Bundle items as ``NodeWithScore``, in bundle order.

    ``score`` is deliberately left ``None``. Bundle order is the daemon's
    *presentation* order -- facts by ``(entity, key, fact_id)``, sections in
    normative order -- and is explicitly **not** a relevance ranking. Filling
    in a synthetic descending score would let downstream LlamaIndex components
    re-sort or threshold on a number this adapter invented, which is exactly
    the re-deciding the conformance suite forbids.
    """
    _require_llamaindex()
    from llama_index.core.schema import NodeWithScore, TextNode

    return [
        NodeWithScore(
            node=TextNode(
                id_=item.id,
                text=item.text,
                metadata={"crux_id": item.id, "crux_kind": item.kind, **item.metadata},
            ),
            score=None,
        )
        for item in bundle.items
    ]


def _build_retriever_class() -> Any:
    """Define the retriever lazily so importing this module never needs LlamaIndex."""
    _require_llamaindex()
    from llama_index.core.retrievers import BaseRetriever
    from llama_index.core.schema import NodeWithScore, QueryBundle

    class _CruxContextRetriever(BaseRetriever):
        """Retrieve Crux memory as LlamaIndex nodes.

        The daemon performs the recall; the query string is passed through to
        ``/v1/context`` rather than being matched client-side.
        """

        def __init__(
            self,
            client: Any,
            *,
            entity: str | None = None,
            session_id: str | None = None,
            token_budget: int | None = None,
            **kwargs: Any,
        ) -> None:
            self._client = client
            self._entity = entity
            self._session_id = session_id
            self._token_budget = token_budget
            super().__init__(**kwargs)

        def _retrieve(self, query_bundle: QueryBundle) -> list[NodeWithScore]:
            bundle = fetch_bundle(
                self._client,
                query=query_bundle.query_str or None,
                entity=self._entity,
                session_id=self._session_id,
                token_budget=self._token_budget,
            )
            return to_nodes(bundle)

    return _CruxContextRetriever


def CruxContextRetriever(client: Any, **kwargs: Any) -> Any:  # noqa: N802 - class factory
    """Construct a Crux-backed LlamaIndex retriever.

    A factory rather than a class so importing :mod:`crux_adapters` does not
    require LlamaIndex to be installed.
    """
    return _build_retriever_class()(client, **kwargs)


def adapter_entrypoint(client: Any, **options: Any) -> ContextBundle:
    """Conformance hook: the bundle this adapter would inject."""
    return fetch_bundle(client, **options)


def adapter_items(bundle: ContextBundle) -> list[ContextItem]:
    """Conformance hook: the items this adapter presents, in its own order.

    LlamaIndex nodes map 1:1 onto bundle items, so this is the identity --
    stated rather than assumed, because that is the property under test.
    """
    return list(bundle.items)
