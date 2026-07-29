# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.

"""Synchronous and asynchronous CoreCrux HTTP clients."""

from __future__ import annotations

from typing import Any

import httpx

from .errors import CoreCruxError
from .types import (
    Fact,
    FactQueryResult,
    SessionState,
    StoreFact,
    TextSearchCoverage,
    TextSearchHit,
    TextSearchMeta,
    TextSearchResult,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _headers(token: str | None) -> dict[str, str]:
    h: dict[str, str] = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _raise_for_status(resp: httpx.Response) -> None:
    if resp.status_code < 400:
        return
    ct = resp.headers.get("content-type", "")
    if ct.startswith("application/json") or ct.startswith("application/problem+json"):
        body = resp.json()
    else:
        body = {}
    raise CoreCruxError(
        resp.status_code,
        body.get("detail", resp.text),
        body.get("type", ""),
    )


def _parse_json(resp: httpx.Response) -> dict[str, Any]:
    _raise_for_status(resp)
    if not resp.content:
        return {}
    return resp.json()


def _to_fact(d: dict[str, Any]) -> Fact:
    return Fact(
        fact_id=d["fact_id"],
        entity=d["entity"],
        key=d["key"],
        value=d["value"],
        confidence=d["confidence"],
        stored_at=d["stored_at"],
        tokens=d["tokens"],
        deleted=d["deleted"],
        version=d.get("version", 1),
        source_receipt=d.get("source_receipt"),
        supersedes=d.get("supersedes"),
        private=d.get("private", False),
    )


def _to_session(d: dict[str, Any]) -> SessionState:
    return SessionState(
        session_id=d["session_id"],
        state=d["state"],
        updated_at=d["updated_at"],
        total_tokens=d["total_tokens"],
        expires_at=d.get("expires_at"),
    )


def _to_text_search_result(d: dict[str, Any]) -> TextSearchResult:
    hits = [
        TextSearchHit(
            segment_index=h["segment_index"],
            doc_id=h["doc_id"],
            score=h["score"],
            frame_offset=h["frame_offset"],
            token_count=h["token_count"],
        )
        for h in d.get("results", [])
    ]
    cov_raw = d.get("coverage", {})
    coverage = TextSearchCoverage(
        score=cov_raw.get("score", 0.0),
        gaps=cov_raw.get("gaps", []),
        below_floor=cov_raw.get("below_floor", 0),
    )
    meta_raw = d.get("meta", {})
    meta = TextSearchMeta(
        backend=meta_raw.get("backend", ""),
        took_ms=meta_raw.get("took_ms", 0),
        segments_searched=meta_raw.get("segments_searched", 0),
        total_docs=meta_raw.get("total_docs", 0),
        total_candidates=meta_raw.get("total_candidates", 0),
    )
    return TextSearchResult(
        results=hits,
        coverage=coverage,
        meta=meta,
        tokens_used=d.get("tokens_used"),
        tokens_available=d.get("tokens_available"),
        results_omitted=d.get("results_omitted"),
        scan_mode=d.get("scan_mode", False),
    )


def _store_fact_payload(fact: StoreFact) -> dict[str, Any]:
    d: dict[str, Any] = {
        "entity": fact.entity,
        "key": fact.key,
        "value": fact.value,
        "confidence": fact.confidence,
        "private": fact.private,
    }
    if fact.source_receipt is not None:
        d["source_receipt"] = fact.source_receipt
    return d


# ---------------------------------------------------------------------------
# Synchronous client
# ---------------------------------------------------------------------------

class CoreCruxClient:
    """Synchronous CoreCrux HTTP client.

    Usage::

        with CoreCruxClient("http://localhost:14800", token="...") as client:
            info = client.healthz()
            fact = client.store_fact(StoreFact(entity="user", key="name", value="Alice"))
    """

    def __init__(
        self,
        base_url: str = "http://localhost:14800",
        token: str | None = None,
        *,
        timeout: float = 30.0,
    ):
        self._client = httpx.Client(
            base_url=base_url,
            headers=_headers(token),
            timeout=timeout,
        )

    # -- context manager --

    def __enter__(self) -> CoreCruxClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._client.close()

    # -- internal --

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        resp = self._client.request(method, path, **kwargs)
        return _parse_json(resp)

    # -- health --

    def healthz(self) -> dict[str, Any]:
        """GET /healthz -- node health status."""
        return self._request("GET", "/healthz")

    def readyz(self) -> dict[str, Any]:
        """GET /readyz -- node readiness checks."""
        return self._request("GET", "/readyz")

    def version(self) -> dict[str, Any]:
        """GET /v1/version -- build version and feature flags."""
        return self._request("GET", "/v1/version")

    # -- facts --

    def store_fact(self, fact: StoreFact) -> Fact:
        """PUT /v1/facts -- create or update a single fact."""
        data = self._request("PUT", "/v1/facts", json=_store_fact_payload(fact))
        return _to_fact(data)

    def store_facts(self, facts: list[StoreFact]) -> list[Fact]:
        """PUT /v1/facts/bulk -- create multiple facts at once."""
        payload = [_store_fact_payload(f) for f in facts]
        data = self._request("PUT", "/v1/facts/bulk", json=payload)
        return [_to_fact(f) for f in data.get("facts", [])]

    def get_fact(self, fact_id: str) -> Fact | None:
        """GET /v1/facts/{factId} -- retrieve a fact by ID.

        Returns ``None`` if the fact does not exist (404).
        """
        try:
            data = self._request("GET", f"/v1/facts/{fact_id}")
            return _to_fact(data)
        except CoreCruxError as exc:
            if exc.status_code == 404:
                return None
            raise

    def delete_fact(self, fact_id: str) -> bool:
        """DELETE /v1/facts/{factId} -- soft-delete a fact.

        Returns ``True`` if deleted, ``False`` if the fact was not found.
        """
        try:
            data = self._request("DELETE", f"/v1/facts/{fact_id}")
            return data.get("deleted", False)
        except CoreCruxError as exc:
            if exc.status_code == 404:
                return False
            raise

    def get_facts_by_entity(self, entity: str) -> list[Fact]:
        """GET /v1/facts/entity/{entity} -- list all facts for an entity."""
        data = self._request("GET", f"/v1/facts/entity/{entity}")
        return [_to_fact(f) for f in data.get("facts", [])]

    def query_facts(
        self,
        query: str | None = None,
        *,
        entity: str | None = None,
        entity_prefix: str | None = None,
        top_k: int | None = None,
        token_budget: int | None = None,
    ) -> FactQueryResult:
        """GET /v1/facts -- query facts with BM25 text search and filters."""
        params: dict[str, Any] = {}
        if query is not None:
            params["query"] = query
        if entity is not None:
            params["entity"] = entity
        if entity_prefix is not None:
            params["entity_prefix"] = entity_prefix
        if top_k is not None:
            params["top_k"] = top_k
        if token_budget is not None:
            params["token_budget"] = token_budget
        data = self._request("GET", "/v1/facts", params=params)
        return FactQueryResult(
            facts=[_to_fact(f) for f in data.get("facts", [])],
            total_tokens=data.get("total_tokens", 0),
        )

    def export_facts(
        self,
        *,
        since: str | None = None,
        cursor: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """GET /v1/facts/export -- paginated fact export (including tombstones)."""
        params: dict[str, Any] = {}
        if since is not None:
            params["since"] = since
        if cursor is not None:
            params["cursor"] = cursor
        if limit is not None:
            params["limit"] = limit
        return self._request("GET", "/v1/facts/export", params=params)

    # -- sessions --

    def put_session(self, session_id: str, state: dict[str, Any]) -> SessionState:
        """PUT /v1/sessions/{sessionId}/state -- store session state."""
        data = self._request("PUT", f"/v1/sessions/{session_id}/state", json=state)
        return _to_session(data)

    def get_session(self, session_id: str) -> SessionState | None:
        """GET /v1/sessions/{sessionId}/state -- retrieve session state.

        Returns ``None`` if the session does not exist (404).
        """
        try:
            data = self._request("GET", f"/v1/sessions/{session_id}/state")
            return _to_session(data)
        except CoreCruxError as exc:
            if exc.status_code == 404:
                return None
            raise

    # -- query --

    def text_search(
        self,
        tenant_id: str,
        query: str,
        *,
        limit: int = 10,
        token_budget: int | None = None,
        min_score: float | None = None,
        mode: str | None = None,
    ) -> TextSearchResult:
        """POST /v1/query/text-search -- BM25 full-text search over segments."""
        body: dict[str, Any] = {
            "tenant_id": tenant_id,
            "query": query,
            "limit": limit,
        }
        if token_budget is not None:
            body["token_budget"] = token_budget
        if min_score is not None:
            body["min_score"] = min_score
        if mode is not None:
            body["mode"] = mode
        data = self._request("POST", "/v1/query/text-search", json=body)
        return _to_text_search_result(data)

    def text_search_expand(
        self,
        tenant_id: str,
        result_ids: list[dict[str, int]],
    ) -> dict[str, Any]:
        """POST /v1/query/text-search/expand -- expand scan-mode results.

        ``result_ids`` should be a list of dicts with ``segment_index`` and ``doc_id`` keys.
        """
        body: dict[str, Any] = {
            "tenant_id": tenant_id,
            "result_ids": result_ids,
        }
        return self._request("POST", "/v1/query/text-search/expand", json=body)

    def graph_expand(
        self,
        tenant_id: str,
        seed_artifact_ids: list[int],
        *,
        edge_types: list[str] | None = None,
        max_hops: int = 2,
        budget: int = 50,
        min_confidence: float = 0.0,
        include_state: bool = False,
    ) -> dict[str, Any]:
        """POST /v1/query/graph-expand -- traverse the artifact relation graph."""
        body: dict[str, Any] = {
            "tenant_id": tenant_id,
            "seed_artifact_ids": seed_artifact_ids,
            "max_hops": max_hops,
            "budget": budget,
            "min_confidence": min_confidence,
            "include_state": include_state,
        }
        if edge_types is not None:
            body["edge_types"] = edge_types
        return self._request("POST", "/v1/query/graph-expand", json=body)

    def time_range(
        self,
        tenant_id: str,
        start_micros: int,
        end_micros: int,
        *,
        artifact_ids: list[int] | None = None,
        include_relations: bool = False,
        limit: int = 100,
    ) -> dict[str, Any]:
        """POST /v1/query/time-range -- query artifacts changed within a time window."""
        body: dict[str, Any] = {
            "tenant_id": tenant_id,
            "start_micros": start_micros,
            "end_micros": end_micros,
            "include_relations": include_relations,
            "limit": limit,
        }
        if artifact_ids is not None:
            body["artifact_ids"] = artifact_ids
        return self._request("POST", "/v1/query/time-range", json=body)


# ---------------------------------------------------------------------------
# Asynchronous client
# ---------------------------------------------------------------------------

class AsyncCoreCruxClient:
    """Asynchronous CoreCrux HTTP client (uses ``httpx.AsyncClient``).

    Usage::

        async with AsyncCoreCruxClient("http://localhost:14800", token="...") as client:
            info = await client.healthz()
            fact = await client.store_fact(StoreFact(entity="user", key="name", value="Alice"))
    """

    def __init__(
        self,
        base_url: str = "http://localhost:14800",
        token: str | None = None,
        *,
        timeout: float = 30.0,
    ):
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers=_headers(token),
            timeout=timeout,
        )

    # -- context manager --

    async def __aenter__(self) -> AsyncCoreCruxClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        await self._client.aclose()

    # -- internal --

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        resp = await self._client.request(method, path, **kwargs)
        return _parse_json(resp)

    # -- health --

    async def healthz(self) -> dict[str, Any]:
        """GET /healthz -- node health status."""
        return await self._request("GET", "/healthz")

    async def readyz(self) -> dict[str, Any]:
        """GET /readyz -- node readiness checks."""
        return await self._request("GET", "/readyz")

    async def version(self) -> dict[str, Any]:
        """GET /v1/version -- build version and feature flags."""
        return await self._request("GET", "/v1/version")

    # -- facts --

    async def store_fact(self, fact: StoreFact) -> Fact:
        """PUT /v1/facts -- create or update a single fact."""
        data = await self._request("PUT", "/v1/facts", json=_store_fact_payload(fact))
        return _to_fact(data)

    async def store_facts(self, facts: list[StoreFact]) -> list[Fact]:
        """PUT /v1/facts/bulk -- create multiple facts at once."""
        payload = [_store_fact_payload(f) for f in facts]
        data = await self._request("PUT", "/v1/facts/bulk", json=payload)
        return [_to_fact(f) for f in data.get("facts", [])]

    async def get_fact(self, fact_id: str) -> Fact | None:
        """GET /v1/facts/{factId} -- retrieve a fact by ID."""
        try:
            data = await self._request("GET", f"/v1/facts/{fact_id}")
            return _to_fact(data)
        except CoreCruxError as exc:
            if exc.status_code == 404:
                return None
            raise

    async def delete_fact(self, fact_id: str) -> bool:
        """DELETE /v1/facts/{factId} -- soft-delete a fact."""
        try:
            data = await self._request("DELETE", f"/v1/facts/{fact_id}")
            return data.get("deleted", False)
        except CoreCruxError as exc:
            if exc.status_code == 404:
                return False
            raise

    async def get_facts_by_entity(self, entity: str) -> list[Fact]:
        """GET /v1/facts/entity/{entity} -- list all facts for an entity."""
        data = await self._request("GET", f"/v1/facts/entity/{entity}")
        return [_to_fact(f) for f in data.get("facts", [])]

    async def query_facts(
        self,
        query: str | None = None,
        *,
        entity: str | None = None,
        entity_prefix: str | None = None,
        top_k: int | None = None,
        token_budget: int | None = None,
    ) -> FactQueryResult:
        """GET /v1/facts -- query facts with BM25 text search and filters."""
        params: dict[str, Any] = {}
        if query is not None:
            params["query"] = query
        if entity is not None:
            params["entity"] = entity
        if entity_prefix is not None:
            params["entity_prefix"] = entity_prefix
        if top_k is not None:
            params["top_k"] = top_k
        if token_budget is not None:
            params["token_budget"] = token_budget
        data = await self._request("GET", "/v1/facts", params=params)
        return FactQueryResult(
            facts=[_to_fact(f) for f in data.get("facts", [])],
            total_tokens=data.get("total_tokens", 0),
        )

    async def export_facts(
        self,
        *,
        since: str | None = None,
        cursor: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """GET /v1/facts/export -- paginated fact export (including tombstones)."""
        params: dict[str, Any] = {}
        if since is not None:
            params["since"] = since
        if cursor is not None:
            params["cursor"] = cursor
        if limit is not None:
            params["limit"] = limit
        return await self._request("GET", "/v1/facts/export", params=params)

    # -- sessions --

    async def put_session(self, session_id: str, state: dict[str, Any]) -> SessionState:
        """PUT /v1/sessions/{sessionId}/state -- store session state."""
        data = await self._request("PUT", f"/v1/sessions/{session_id}/state", json=state)
        return _to_session(data)

    async def get_session(self, session_id: str) -> SessionState | None:
        """GET /v1/sessions/{sessionId}/state -- retrieve session state."""
        try:
            data = await self._request("GET", f"/v1/sessions/{session_id}/state")
            return _to_session(data)
        except CoreCruxError as exc:
            if exc.status_code == 404:
                return None
            raise

    # -- query --

    async def text_search(
        self,
        tenant_id: str,
        query: str,
        *,
        limit: int = 10,
        token_budget: int | None = None,
        min_score: float | None = None,
        mode: str | None = None,
    ) -> TextSearchResult:
        """POST /v1/query/text-search -- BM25 full-text search over segments."""
        body: dict[str, Any] = {
            "tenant_id": tenant_id,
            "query": query,
            "limit": limit,
        }
        if token_budget is not None:
            body["token_budget"] = token_budget
        if min_score is not None:
            body["min_score"] = min_score
        if mode is not None:
            body["mode"] = mode
        data = await self._request("POST", "/v1/query/text-search", json=body)
        return _to_text_search_result(data)

    async def text_search_expand(
        self,
        tenant_id: str,
        result_ids: list[dict[str, int]],
    ) -> dict[str, Any]:
        """POST /v1/query/text-search/expand -- expand scan-mode results."""
        body: dict[str, Any] = {
            "tenant_id": tenant_id,
            "result_ids": result_ids,
        }
        return await self._request("POST", "/v1/query/text-search/expand", json=body)

    async def graph_expand(
        self,
        tenant_id: str,
        seed_artifact_ids: list[int],
        *,
        edge_types: list[str] | None = None,
        max_hops: int = 2,
        budget: int = 50,
        min_confidence: float = 0.0,
        include_state: bool = False,
    ) -> dict[str, Any]:
        """POST /v1/query/graph-expand -- traverse the artifact relation graph."""
        body: dict[str, Any] = {
            "tenant_id": tenant_id,
            "seed_artifact_ids": seed_artifact_ids,
            "max_hops": max_hops,
            "budget": budget,
            "min_confidence": min_confidence,
            "include_state": include_state,
        }
        if edge_types is not None:
            body["edge_types"] = edge_types
        return await self._request("POST", "/v1/query/graph-expand", json=body)

    async def time_range(
        self,
        tenant_id: str,
        start_micros: int,
        end_micros: int,
        *,
        artifact_ids: list[int] | None = None,
        include_relations: bool = False,
        limit: int = 100,
    ) -> dict[str, Any]:
        """POST /v1/query/time-range -- query artifacts changed within a time window."""
        body: dict[str, Any] = {
            "tenant_id": tenant_id,
            "start_micros": start_micros,
            "end_micros": end_micros,
            "include_relations": include_relations,
            "limit": limit,
        }
        if artifact_ids is not None:
            body["artifact_ids"] = artifact_ids
        return await self._request("POST", "/v1/query/time-range", json=body)
