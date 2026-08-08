# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.

"""Synchronous and asynchronous CueCrux HTTP clients."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx

from .errors import CueCruxError
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
    raise CueCruxError(
        resp.status_code,
        body.get("detail", resp.text),
        body.get("type", ""),
    )


def _parse_json(resp: httpx.Response) -> dict[str, Any]:
    _raise_for_status(resp)
    if not resp.content:
        return {}
    return resp.json()


def _params(**kwargs: Any) -> dict[str, Any]:
    """Drop ``None`` entries so optional query parameters are simply absent.

    Sending ``types=`` explicitly is not the same as omitting it: the daemon
    reads a blank filter as "match nothing", not "stream everything".
    """
    return {k: v for k, v in kwargs.items() if v is not None}


def _body(**kwargs: Any) -> dict[str, Any]:
    """Drop ``None`` entries so the daemon's ``#[serde(default)]`` applies."""
    return {k: v for k, v in kwargs.items() if v is not None}


def _sse_event(block: str) -> dict[str, Any] | None:
    """Parse one SSE block into its decoded JSON ``data`` payload.

    Returns ``None`` for keep-alive comments and for any block without a
    ``data:`` field. The daemon sends a comment every 15s to hold the
    connection open, and those must not surface as events.
    """
    data_lines = [
        line[5:].lstrip() if line.startswith("data:") else line[len("data") :]
        for line in block.splitlines()
        if line.startswith("data:") or line == "data"
    ]
    if not data_lines:
        return None
    try:
        return json.loads("\n".join(data_lines))
    except json.JSONDecodeError:
        return None


def _sse_blocks(lines: Any) -> Any:
    """Group an iterable of SSE lines into ``\\n\\n``-delimited blocks."""
    buf: list[str] = []
    for line in lines:
        if line == "":
            if buf:
                yield "\n".join(buf)
                buf = []
        else:
            buf.append(line)
    if buf:
        yield "\n".join(buf)


async def _sse_blocks_async(lines: Any) -> Any:
    """:func:`_sse_blocks` over an async line iterator."""
    buf: list[str] = []
    async for line in lines:
        if line == "":
            if buf:
                yield "\n".join(buf)
                buf = []
        else:
            buf.append(line)
    if buf:
        yield "\n".join(buf)


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

class CueCruxClient:
    """Synchronous CueCrux HTTP client.

    Usage::

        with CueCruxClient("http://localhost:14800", token="...") as client:
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

    def __enter__(self) -> CueCruxClient:
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
        except CueCruxError as exc:
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
        except CueCruxError as exc:
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
        except CueCruxError as exc:
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

    # -- context --

    def context(
        self,
        *,
        session_id: str | None = None,
        entity: str | None = None,
        query: str | None = None,
        token_budget: int | None = None,
    ) -> dict[str, Any]:
        """GET /v1/context -- the provider-neutral injection bundle.

        Requires ``CORECRUXD_CONTEXT_SURFACE=1`` on the daemon; the route 404s
        when the surface is off, so the capability is invisible rather than
        half-alive.

        The response is the flattened wire envelope, not the daemon's internal
        ``ContextBundle`` struct: ``sections`` sits at the top level rather
        than under a ``stable`` key. ``stable_hash`` covers only the stable
        region (``bundle_version`` + ordered ``sections``), so it is byte-stable
        across calls for an unchanged fact-chain head.
        """
        return self._request(
            "GET",
            "/v1/context",
            params=_params(
                session_id=session_id, entity=entity, query=query, token_budget=token_budget
            ),
        )

    def post_context(self, **options: Any) -> dict[str, Any]:
        """POST /v1/context -- same bundle, options in the body.

        Prefer this when ``query`` is long enough to strain a URL.
        """
        return self._request("POST", "/v1/context", json=_body(**options))

    def context_markdown(self, **options: Any) -> str:
        """GET /v1/context?render=markdown -- the boot-banner rendering.

        Returns ``text/markdown``, so this bypasses the JSON parse path.
        """
        resp = self._client.request(
            "GET", "/v1/context", params=_params(render="markdown", **options)
        )
        _raise_for_status(resp)
        return resp.text

    def context_messages(self, **options: Any) -> dict[str, Any]:
        """GET /v1/context?render=openai_messages -- an OpenAI messages fragment."""
        return self._request(
            "GET", "/v1/context", params=_params(render="openai_messages", **options)
        )

    # -- review: auto-capture candidates --

    def extract_memory(
        self,
        text: str,
        *,
        session_id: str | None = None,
        profile: str | None = None,
        session_date: str | None = None,
    ) -> dict[str, Any]:
        """POST /v1/memory/extract -- mine transcript text into review candidates.

        Candidates land in the ``__candidate_fact__::`` review namespace and
        never appear in ``query_facts`` recall until promoted. Requires
        ``CORECRUXD_AUTO_CAPTURE=1``.
        """
        return self._request(
            "POST",
            "/v1/memory/extract",
            json=_body(
                text=text, session_id=session_id, profile=profile, session_date=session_date
            ),
        )

    def list_candidates(self, *, status: str | None = None) -> dict[str, Any]:
        """GET /v1/memory/candidates -- list candidates, optionally by status.

        ``status`` is one of ``candidate``, ``promoted``, ``rejected``.
        """
        return self._request("GET", "/v1/memory/candidates", params=_params(status=status))

    def promote_candidate(
        self,
        candidate_id: str,
        *,
        reviewer: str | None = None,
        auto_threshold: float | None = None,
    ) -> dict[str, Any]:
        """POST /v1/memory/candidates/{id}/promote -- promote to a real fact.

        The gate is fail-closed: with ``auto_threshold`` set, an unscored or
        below-threshold candidate is refused (422) rather than promoted.
        """
        return self._request(
            "POST",
            f"/v1/memory/candidates/{candidate_id}/promote",
            json=_body(reviewer=reviewer, auto_threshold=auto_threshold),
        )

    def reject_candidate(self, candidate_id: str, reason: str) -> dict[str, Any]:
        """POST /v1/memory/candidates/{id}/reject -- reject with a reason."""
        return self._request(
            "POST", f"/v1/memory/candidates/{candidate_id}/reject", json={"reason": reason}
        )

    # -- review: contradictions, queue, expiries --

    def review_contradictions(self, *, limit: int | None = None) -> dict[str, Any]:
        """GET /v1/console/review/contradictions -- run a LIVE contradiction pass."""
        return self._request(
            "GET", "/v1/console/review/contradictions", params=_params(limit=limit)
        )

    def review_queue(self, *, limit: int | None = None) -> dict[str, Any]:
        """GET /v1/console/review/queue -- surfaced scheduler review receipts.

        Distinct from :meth:`review_contradictions`, which runs a live pass.
        """
        return self._request("GET", "/v1/console/review/queue", params=_params(limit=limit))

    def apply_expiries(self, fact_ids: list[str]) -> dict[str, Any]:
        """POST /v1/console/review/expiries -- apply reviewed expiry proposals.

        Every id is re-validated at apply time; ids that became protected, were
        re-verified fresh, or gained confidence are skipped, never deleted.
        Capped at 500 ids per request.
        """
        return self._request(
            "POST", "/v1/console/review/expiries", json={"fact_ids": fact_ids}
        )

    # -- consolidation --

    def consolidate(
        self,
        entity: str,
        key: str,
        canonical_value: str,
        target_fact_ids: list[str],
        **options: Any,
    ) -> dict[str, Any]:
        """POST /v1/console/review/consolidations -- merge facts atomically.

        Emits an Ed25519-signed, offline-verifiable diff receipt. Facts at or
        above ``protected_confidence_floor`` (0.99 by default) are never merged.
        The scheduler itself stays proposal-only -- this is the explicit commit.
        """
        return self._request(
            "POST",
            "/v1/console/review/consolidations",
            # `consolidation_id` has no serde default daemon-side, so omitting
            # it is a 422 even though the handler generates one for a BLANK
            # value. Send "" and let the daemon mint `console-<uuid>`.
            json=_body(
                consolidation_id=options.pop("consolidation_id", ""),
                entity=entity,
                key=key,
                canonical_value=canonical_value,
                target_fact_ids=target_fact_ids,
                **options,
            ),
        )

    def undo_consolidation(
        self, canonical_fact_id: str, **options: Any
    ) -> dict[str, Any]:
        """POST /v1/console/review/consolidations/undo -- reverse a consolidation.

        Idempotent: undoing an already-undone consolidation returns
        ``status = "already_undone"`` rather than failing.
        """
        return self._request(
            "POST",
            "/v1/console/review/consolidations/undo",
            json=_body(canonical_fact_id=canonical_fact_id, **options),
        )

    # -- ingest --

    def local_ingest(
        self,
        tenant_id: str,
        corpus_id: str,
        documents: list[dict[str, Any]],
        *,
        semantic_profile: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """POST /v1/local/ingest -- ingest documents into a local corpus.

        Chunks without a ``dense_vector`` are embedded server-side, so this
        works offline with no external embedder. Caps: 4096 documents and
        65536 chunks per request, 4 MiB per chunk.
        """
        return self._request(
            "POST",
            "/v1/local/ingest",
            json=_body(
                tenant_id=tenant_id,
                corpus_id=corpus_id,
                documents=documents,
                semantic_profile=semantic_profile,
            ),
        )

    def import_memory_pack(
        self,
        tenant_id: str,
        pack: dict[str, Any],
        *,
        dry_run: bool = False,
        principal_map: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """POST /v1/memory/import -- import a signed ``CruxPack``.

        Requires ``CRUX_MEMORY_IMPORT=1``. ``tenant_id`` must equal the pack
        manifest's tenant -- there is no override.
        """
        return self._request(
            "POST",
            "/v1/memory/import",
            json=_body(
                tenant_id=tenant_id,
                pack=pack,
                dry_run=dry_run,
                principal_map=principal_map,
            ),
        )

    # -- extensions --

    def list_extensions(self) -> dict[str, Any]:
        """GET /v1/extensions -- list installed extensions."""
        return self._request("GET", "/v1/extensions")

    def get_extension(self, extension_id: str) -> dict[str, Any] | None:
        """GET /v1/extensions/{id} -- one extension, or None if absent."""
        try:
            return self._request("GET", f"/v1/extensions/{extension_id}")
        except CueCruxError as err:
            if err.status_code == 404:
                return None
            raise

    def register_extension(self, manifest: dict[str, Any]) -> dict[str, Any]:
        """POST /v1/extensions/register -- register a signed manifest."""
        return self._request("POST", "/v1/extensions/register", json={"manifest": manifest})

    def delete_extension(self, extension_id: str) -> bool:
        """DELETE /v1/extensions/{id} -- uninstall. False if not installed."""
        try:
            self._request("DELETE", f"/v1/extensions/{extension_id}")
            return True
        except CueCruxError as err:
            if err.status_code == 404:
                return False
            raise

    def list_registry_entries(self) -> dict[str, Any]:
        """GET /v1/extensions/registry -- the curator-signed community index."""
        return self._request("GET", "/v1/extensions/registry")

    def install_from_registry(
        self, extension_id: str, *, index_path: str | None = None
    ) -> dict[str, Any]:
        """POST /v1/extensions/install-from-registry -- install from the cached index."""
        return self._request(
            "POST",
            "/v1/extensions/install-from-registry",
            json=_body(id=extension_id, index_path=index_path),
        )

    def list_trusted_keys(self) -> dict[str, Any]:
        """GET /v1/extensions/keys -- trusted signing keys."""
        return self._request("GET", "/v1/extensions/keys")

    def add_trusted_key(
        self,
        passport_fpr: str,
        public_key_hex: str,
        trust_tier: str,
        *,
        added_by: str | None = None,
    ) -> dict[str, Any]:
        """POST /v1/extensions/keys -- trust a signing key at a tier."""
        return self._request(
            "POST",
            "/v1/extensions/keys",
            json=_body(
                passport_fpr=passport_fpr,
                public_key_hex=public_key_hex,
                trust_tier=trust_tier,
                added_by=added_by,
            ),
        )

    def delete_trusted_key(self, passport_fpr: str) -> dict[str, Any]:
        """DELETE /v1/extensions/keys/{passport_fpr} -- untrust a signing key."""
        return self._request("DELETE", f"/v1/extensions/keys/{passport_fpr}")

    def list_grants(self, extension_id: str) -> dict[str, Any]:
        """GET /v1/extensions/{id}/grants -- grants issued for an extension."""
        return self._request("GET", f"/v1/extensions/{extension_id}/grants")

    def issue_grant(self, extension_id: str, passport_fpr: str, **options: Any) -> dict[str, Any]:
        """POST /v1/extensions/{id}/grants -- issue a per-passport capability grant."""
        return self._request(
            "POST",
            f"/v1/extensions/{extension_id}/grants",
            json=_body(passport_fpr=passport_fpr, **options),
        )

    def revoke_grant(self, extension_id: str, passport_fpr: str) -> dict[str, Any]:
        """DELETE /v1/extensions/{id}/grants/{passport_fpr} -- revoke a grant."""
        return self._request(
            "DELETE", f"/v1/extensions/{extension_id}/grants/{passport_fpr}"
        )

    def invoke_extension_tool(
        self,
        extension_id: str,
        tool_name: str,
        *,
        args: dict[str, Any] | None = None,
        passport_fpr: str | None = None,
    ) -> dict[str, Any]:
        """POST /v1/extensions/{id}/tools/{tool}/invoke -- dispatch one tool.

        The caller's passport must hold a grant naming this tool.
        """
        return self._request(
            "POST",
            f"/v1/extensions/{extension_id}/tools/{tool_name}/invoke",
            json=_body(args=args if args is not None else {}, passport_fpr=passport_fpr),
        )

    # -- events (SSE) --

    def subscribe_events(
        self, *, types: list[str] | None = None
    ) -> Iterator[dict[str, Any]]:
        """GET /v1/events/stream -- yield mutation events as they arrive.

        The stream is infinite; break out of the loop (or close the client) to
        disconnect. Keep-alive comments are skipped.

        Usage::

            for event in client.subscribe_events(types=["fact.stored"]):
                print(event["type"], event["fact_id"])
                break
        """
        params = _params(types=",".join(types) if types else None)
        with self._client.stream("GET", "/v1/events/stream", params=params) as resp:
            if resp.status_code >= 400:
                resp.read()  # a streamed error body is not loaded until read
            _raise_for_status(resp)
            for block in _sse_blocks(resp.iter_lines()):
                event = _sse_event(block)
                if event is not None:
                    yield event


# ---------------------------------------------------------------------------
# Asynchronous client
# ---------------------------------------------------------------------------

class AsyncCueCruxClient:
    """Asynchronous CueCrux HTTP client (uses ``httpx.AsyncClient``).

    Usage::

        async with AsyncCueCruxClient("http://localhost:14800", token="...") as client:
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

    async def __aenter__(self) -> AsyncCueCruxClient:
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
        except CueCruxError as exc:
            if exc.status_code == 404:
                return None
            raise

    async def delete_fact(self, fact_id: str) -> bool:
        """DELETE /v1/facts/{factId} -- soft-delete a fact."""
        try:
            data = await self._request("DELETE", f"/v1/facts/{fact_id}")
            return data.get("deleted", False)
        except CueCruxError as exc:
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
        except CueCruxError as exc:
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

    # -- context --

    async def context(
        self,
        *,
        session_id: str | None = None,
        entity: str | None = None,
        query: str | None = None,
        token_budget: int | None = None,
    ) -> dict[str, Any]:
        """GET /v1/context -- the provider-neutral injection bundle.

        Requires ``CORECRUXD_CONTEXT_SURFACE=1`` on the daemon; the route 404s
        when the surface is off, so the capability is invisible rather than
        half-alive.

        The response is the flattened wire envelope, not the daemon's internal
        ``ContextBundle`` struct: ``sections`` sits at the top level rather
        than under a ``stable`` key. ``stable_hash`` covers only the stable
        region (``bundle_version`` + ordered ``sections``), so it is byte-stable
        across calls for an unchanged fact-chain head.
        """
        return await self._request(
            "GET",
            "/v1/context",
            params=_params(
                session_id=session_id, entity=entity, query=query, token_budget=token_budget
            ),
        )

    async def post_context(self, **options: Any) -> dict[str, Any]:
        """POST /v1/context -- same bundle, options in the body.

        Prefer this when ``query`` is long enough to strain a URL.
        """
        return await self._request("POST", "/v1/context", json=_body(**options))

    async def context_markdown(self, **options: Any) -> str:
        """GET /v1/context?render=markdown -- the boot-banner rendering.

        Returns ``text/markdown``, so this bypasses the JSON parse path.
        """
        resp = await self._client.request(
            "GET", "/v1/context", params=_params(render="markdown", **options)
        )
        _raise_for_status(resp)
        return resp.text

    async def context_messages(self, **options: Any) -> dict[str, Any]:
        """GET /v1/context?render=openai_messages -- an OpenAI messages fragment."""
        return await self._request(
            "GET", "/v1/context", params=_params(render="openai_messages", **options)
        )

    # -- review: auto-capture candidates --

    async def extract_memory(
        self,
        text: str,
        *,
        session_id: str | None = None,
        profile: str | None = None,
        session_date: str | None = None,
    ) -> dict[str, Any]:
        """POST /v1/memory/extract -- mine transcript text into review candidates.

        Candidates land in the ``__candidate_fact__::`` review namespace and
        never appear in ``query_facts`` recall until promoted. Requires
        ``CORECRUXD_AUTO_CAPTURE=1``.
        """
        return await self._request(
            "POST",
            "/v1/memory/extract",
            json=_body(
                text=text, session_id=session_id, profile=profile, session_date=session_date
            ),
        )

    async def list_candidates(self, *, status: str | None = None) -> dict[str, Any]:
        """GET /v1/memory/candidates -- list candidates, optionally by status.

        ``status`` is one of ``candidate``, ``promoted``, ``rejected``.
        """
        return await self._request("GET", "/v1/memory/candidates", params=_params(status=status))

    async def promote_candidate(
        self,
        candidate_id: str,
        *,
        reviewer: str | None = None,
        auto_threshold: float | None = None,
    ) -> dict[str, Any]:
        """POST /v1/memory/candidates/{id}/promote -- promote to a real fact.

        The gate is fail-closed: with ``auto_threshold`` set, an unscored or
        below-threshold candidate is refused (422) rather than promoted.
        """
        return await self._request(
            "POST",
            f"/v1/memory/candidates/{candidate_id}/promote",
            json=_body(reviewer=reviewer, auto_threshold=auto_threshold),
        )

    async def reject_candidate(self, candidate_id: str, reason: str) -> dict[str, Any]:
        """POST /v1/memory/candidates/{id}/reject -- reject with a reason."""
        return await self._request(
            "POST", f"/v1/memory/candidates/{candidate_id}/reject", json={"reason": reason}
        )

    # -- review: contradictions, queue, expiries --

    async def review_contradictions(self, *, limit: int | None = None) -> dict[str, Any]:
        """GET /v1/console/review/contradictions -- run a LIVE contradiction pass."""
        return await self._request(
            "GET", "/v1/console/review/contradictions", params=_params(limit=limit)
        )

    async def review_queue(self, *, limit: int | None = None) -> dict[str, Any]:
        """GET /v1/console/review/queue -- surfaced scheduler review receipts.

        Distinct from :meth:`review_contradictions`, which runs a live pass.
        """
        return await self._request("GET", "/v1/console/review/queue", params=_params(limit=limit))

    async def apply_expiries(self, fact_ids: list[str]) -> dict[str, Any]:
        """POST /v1/console/review/expiries -- apply reviewed expiry proposals.

        Every id is re-validated at apply time; ids that became protected, were
        re-verified fresh, or gained confidence are skipped, never deleted.
        Capped at 500 ids per request.
        """
        return await self._request(
            "POST", "/v1/console/review/expiries", json={"fact_ids": fact_ids}
        )

    # -- consolidation --

    async def consolidate(
        self,
        entity: str,
        key: str,
        canonical_value: str,
        target_fact_ids: list[str],
        **options: Any,
    ) -> dict[str, Any]:
        """POST /v1/console/review/consolidations -- merge facts atomically.

        Emits an Ed25519-signed, offline-verifiable diff receipt. Facts at or
        above ``protected_confidence_floor`` (0.99 by default) are never merged.
        The scheduler itself stays proposal-only -- this is the explicit commit.
        """
        return await self._request(
            "POST",
            "/v1/console/review/consolidations",
            # `consolidation_id` has no serde default daemon-side, so omitting
            # it is a 422 even though the handler generates one for a BLANK
            # value. Send "" and let the daemon mint `console-<uuid>`.
            json=_body(
                consolidation_id=options.pop("consolidation_id", ""),
                entity=entity,
                key=key,
                canonical_value=canonical_value,
                target_fact_ids=target_fact_ids,
                **options,
            ),
        )

    async def undo_consolidation(
        self, canonical_fact_id: str, **options: Any
    ) -> dict[str, Any]:
        """POST /v1/console/review/consolidations/undo -- reverse a consolidation.

        Idempotent: undoing an already-undone consolidation returns
        ``status = "already_undone"`` rather than failing.
        """
        return await self._request(
            "POST",
            "/v1/console/review/consolidations/undo",
            json=_body(canonical_fact_id=canonical_fact_id, **options),
        )

    # -- ingest --

    async def local_ingest(
        self,
        tenant_id: str,
        corpus_id: str,
        documents: list[dict[str, Any]],
        *,
        semantic_profile: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """POST /v1/local/ingest -- ingest documents into a local corpus.

        Chunks without a ``dense_vector`` are embedded server-side, so this
        works offline with no external embedder. Caps: 4096 documents and
        65536 chunks per request, 4 MiB per chunk.
        """
        return await self._request(
            "POST",
            "/v1/local/ingest",
            json=_body(
                tenant_id=tenant_id,
                corpus_id=corpus_id,
                documents=documents,
                semantic_profile=semantic_profile,
            ),
        )

    async def import_memory_pack(
        self,
        tenant_id: str,
        pack: dict[str, Any],
        *,
        dry_run: bool = False,
        principal_map: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """POST /v1/memory/import -- import a signed ``CruxPack``.

        Requires ``CRUX_MEMORY_IMPORT=1``. ``tenant_id`` must equal the pack
        manifest's tenant -- there is no override.
        """
        return await self._request(
            "POST",
            "/v1/memory/import",
            json=_body(
                tenant_id=tenant_id,
                pack=pack,
                dry_run=dry_run,
                principal_map=principal_map,
            ),
        )

    # -- extensions --

    async def list_extensions(self) -> dict[str, Any]:
        """GET /v1/extensions -- list installed extensions."""
        return await self._request("GET", "/v1/extensions")

    async def get_extension(self, extension_id: str) -> dict[str, Any] | None:
        """GET /v1/extensions/{id} -- one extension, or None if absent."""
        try:
            return await self._request("GET", f"/v1/extensions/{extension_id}")
        except CueCruxError as err:
            if err.status_code == 404:
                return None
            raise

    async def register_extension(self, manifest: dict[str, Any]) -> dict[str, Any]:
        """POST /v1/extensions/register -- register a signed manifest."""
        return await self._request("POST", "/v1/extensions/register", json={"manifest": manifest})

    async def delete_extension(self, extension_id: str) -> bool:
        """DELETE /v1/extensions/{id} -- uninstall. False if not installed."""
        try:
            await self._request("DELETE", f"/v1/extensions/{extension_id}")
            return True
        except CueCruxError as err:
            if err.status_code == 404:
                return False
            raise

    async def list_registry_entries(self) -> dict[str, Any]:
        """GET /v1/extensions/registry -- the curator-signed community index."""
        return await self._request("GET", "/v1/extensions/registry")

    async def install_from_registry(
        self, extension_id: str, *, index_path: str | None = None
    ) -> dict[str, Any]:
        """POST /v1/extensions/install-from-registry -- install from the cached index."""
        return await self._request(
            "POST",
            "/v1/extensions/install-from-registry",
            json=_body(id=extension_id, index_path=index_path),
        )

    async def list_trusted_keys(self) -> dict[str, Any]:
        """GET /v1/extensions/keys -- trusted signing keys."""
        return await self._request("GET", "/v1/extensions/keys")

    async def add_trusted_key(
        self,
        passport_fpr: str,
        public_key_hex: str,
        trust_tier: str,
        *,
        added_by: str | None = None,
    ) -> dict[str, Any]:
        """POST /v1/extensions/keys -- trust a signing key at a tier."""
        return await self._request(
            "POST",
            "/v1/extensions/keys",
            json=_body(
                passport_fpr=passport_fpr,
                public_key_hex=public_key_hex,
                trust_tier=trust_tier,
                added_by=added_by,
            ),
        )

    async def delete_trusted_key(self, passport_fpr: str) -> dict[str, Any]:
        """DELETE /v1/extensions/keys/{passport_fpr} -- untrust a signing key."""
        return await self._request("DELETE", f"/v1/extensions/keys/{passport_fpr}")

    async def list_grants(self, extension_id: str) -> dict[str, Any]:
        """GET /v1/extensions/{id}/grants -- grants issued for an extension."""
        return await self._request("GET", f"/v1/extensions/{extension_id}/grants")

    async def issue_grant(self, extension_id: str, passport_fpr: str, **options: Any) -> dict[str, Any]:
        """POST /v1/extensions/{id}/grants -- issue a per-passport capability grant."""
        return await self._request(
            "POST",
            f"/v1/extensions/{extension_id}/grants",
            json=_body(passport_fpr=passport_fpr, **options),
        )

    async def revoke_grant(self, extension_id: str, passport_fpr: str) -> dict[str, Any]:
        """DELETE /v1/extensions/{id}/grants/{passport_fpr} -- revoke a grant."""
        return await self._request(
            "DELETE", f"/v1/extensions/{extension_id}/grants/{passport_fpr}"
        )

    async def invoke_extension_tool(
        self,
        extension_id: str,
        tool_name: str,
        *,
        args: dict[str, Any] | None = None,
        passport_fpr: str | None = None,
    ) -> dict[str, Any]:
        """POST /v1/extensions/{id}/tools/{tool}/invoke -- dispatch one tool.

        The caller's passport must hold a grant naming this tool.
        """
        return await self._request(
            "POST",
            f"/v1/extensions/{extension_id}/tools/{tool_name}/invoke",
            json=_body(args=args if args is not None else {}, passport_fpr=passport_fpr),
        )

    # -- events (SSE) --

    async def subscribe_events(
        self, *, types: list[str] | None = None
    ) -> AsyncIterator[dict[str, Any]]:
        """GET /v1/events/stream -- yield mutation events as they arrive.

        The stream is infinite; break out of the loop (or close the client) to
        disconnect. Keep-alive comments are skipped.

        Usage::

            async for event in client.subscribe_events(types=["fact.stored"]):
                print(event["type"], event["fact_id"])
                break
        """
        params = _params(types=",".join(types) if types else None)
        async with self._client.stream("GET", "/v1/events/stream", params=params) as resp:
            if resp.status_code >= 400:
                await resp.aread()  # a streamed error body is not loaded until read
            _raise_for_status(resp)
            async for block in _sse_blocks_async(resp.aiter_lines()):
                event = _sse_event(block)
                if event is not None:
                    yield event
