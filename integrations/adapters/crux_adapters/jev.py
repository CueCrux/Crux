# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.

"""Signed decision receipts for Jev (TypeSafe AI's System One model).

Jev answers typed questions (Choice / Score / Noul) about a ``state`` and keeps
nothing. :func:`decide` wraps one call so the decision leaves a record:

1. **State from Crux.** ``GET /v1/context`` (via :func:`~.core.fetch_bundle`,
   so the budget is the daemon's to enforce) supplies ``trusted_context``, in
   bundle order. Anything the caller passes -- tool output, email, web pages --
   goes in a separate ``untrusted_input`` field and nowhere else.
2. **One Jev call**, ``POST /v1/systemone``.
3. **A signed ``model_invocation`` receipt** via ``POST /v1/mediation/receipts``
   (daemon flag ``CORECRUXD_STREAM_RECEIPTS=1``), carrying three hashes:
   ``prompt_hash`` over ``{state, questions}``, ``retrieval_set_hash`` over the
   evidence (retrieved item ids and text digests), and ``output_hash`` over
   ``{model, answers}``.
4. **The decision as a fact**, ``jev:<entity>`` / ``decision:<request_id>``,
   with ``source_receipt`` set to that receipt. The fact value carries the
   answers and the evidence list, so both hashes can be recomputed from the
   fact alone and compared with the signed receipt.

A receipt records what was asked, of which model, on what evidence, and what
came back. It does not show the decision was right, or that anyone acted on it.

**Replay** is opt-in. ``decide(..., store_state=True)`` also stores the exact
Jev request as ``__jev__::<entity>`` / ``request:<request_id>``, linked to the
same receipt; :func:`replay` re-sends it (to a newer model if asked) after
checking it still hashes to the receipt's ``prompt_hash``. HTTP fact writes
cannot be private (``private=true`` is MCP-only), so that fact is an ordinary
one: it holds ``untrusted_input`` verbatim, anyone who can read the tenant's
facts can read it, and it is push-eligible on sync. The ``__`` namespace keeps
it out of undirected ``/v1/context`` recall, so a later :func:`decide` cannot
pull the stored untrusted input back in as ``trusted_context``.

Every hash is :func:`digest`: sha256 over compact UTF-8 JSON with key order
**preserved**. Key order is part of what Jev reads -- a Choice's option order
included -- so reordering options is a different prompt and hashes differently.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any

import httpx
from cuecrux_client import CueCruxError, StoreFact

from .core import ContextBundle, ContextItem, fetch_bundle

__all__ = [
    "DecisionNotRecorded",
    "JevDecision",
    "ReplayResult",
    "TamperedRequest",
    "decide",
    "digest",
    "evidence",
    "jev_http",
    "replay",
]

#: A Jev caller: request body in, ``(response JSON, request id)`` out. Wrap the
#: official ``typesafe-sdk`` client in one of these to use its own retry policy.
JevCaller = Callable[[dict[str, Any]], tuple[dict[str, Any], str | None]]


def digest(value: Any) -> str:
    """``sha256:<hex>`` over compact UTF-8 JSON, key order preserved."""
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def evidence(items: Iterable[ContextItem]) -> list[list[str]]:
    """``[[item id, digest(text)], ...]`` in bundle order: the retrieval set.

    Fact ids are version-specific, and the text digest pins aux items (session
    state, dossier) whose ids are not.
    """
    return [[item.id, digest(item.text)] for item in items]


_ATTEMPTS = 3


def _retry_delay(resp: httpx.Response, attempt: int) -> float:
    """``retry-after-ms`` or ``Retry-After`` (seconds) when sane, else 0.5s, 1s, ..."""
    for header, scale in (("retry-after-ms", 0.001), ("retry-after", 1.0)):
        try:
            wait = float(resp.headers[header]) * scale
        except (KeyError, ValueError):
            continue  # absent, or an HTTP-date: fall back to backoff
        if 0 <= wait <= 60:
            return wait
    return min(8.0, 0.5 * 2 ** (attempt - 1))


def jev_http(
    api_key: str | None = None,
    *,
    base_url: str | None = None,
    http: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> JevCaller:
    """A :data:`JevCaller` over the one HTTP endpoint, using ``httpx``.

    ``api_key`` and ``base_url`` fall back to ``TYPESAFE_API_KEY`` and
    ``TYPESAFE_BASE_URL``, the official SDK's variables. The request id comes
    from the ``x-typesafe-request-id`` response header.

    408, 429 and 5xx (529 included) are retried, up to three attempts in all,
    waiting what ``retry-after-ms`` / ``Retry-After`` asks (up to 60s) or else
    backing off exponentially. Other errors (401, 403, 422, ...) are never
    retried. A final failure raises ``httpx.HTTPStatusError``.
    """
    # ponytail: transport errors are not retried (a timed-out POST may have
    # been billed); no jitter. Inject a typesafe-sdk-backed caller for more.
    key = (api_key if api_key is not None else os.environ.get("TYPESAFE_API_KEY", "")).strip()
    if not key:
        raise ValueError("no Jev API key: pass api_key or set TYPESAFE_API_KEY")
    root = base_url or os.environ.get("TYPESAFE_BASE_URL") or "https://api.typesafe.ai"
    url = root.rstrip("/") + "/v1/systemone"

    def call(body: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
        attempt = 1
        while True:
            resp = (http or httpx).post(
                url, json=body, headers={"Authorization": f"Bearer {key}"}, timeout=30.0
            )
            code = resp.status_code
            if attempt < _ATTEMPTS and (code in (408, 429) or code >= 500):
                sleep(_retry_delay(resp, attempt))
                attempt += 1
                continue
            resp.raise_for_status()
            return resp.json(), resp.headers.get("x-typesafe-request-id")

    return call


@dataclass(frozen=True)
class JevDecision:
    """One Jev decision and where its record lives."""

    answers: dict[str, Any]
    """Jev's ``answers`` map, untouched: per question its ``type`` and the
    ``choice`` / ``score`` / ``noul`` value, ``probabilities`` and
    ``confidence``."""
    model_version: str
    """The versioned model that answered (``jev-1.13.0``), not the alias sent."""
    request_id: str | None
    invocation_id: str
    prompt_hash: str
    retrieval_set_hash: str | None
    """``None`` when Crux did not build the state (:mod:`.jev_langchain`)."""
    output_hash: str
    state: Any
    """The exact state sent, for replay against a later model version."""
    bundle: ContextBundle | None
    """The retrieved context. ``bundle.truncated`` means the budget cut it.
    ``None`` when Crux did not build the state."""
    raw: dict[str, Any]
    receipt_id: str | None = None
    fact_id: str | None = None


class DecisionNotRecorded(Exception):
    """Jev answered but the receipt or the fact was not written.

    Raised, not returned, so an unrecorded decision cannot pass for a recorded
    one. ``decision`` still holds the answers (and ``receipt_id`` when only the
    fact failed), so the paid-for call is not lost.
    """

    def __init__(self, message: str, decision: JevDecision):
        super().__init__(message)
        self.decision = decision


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _mint(
    client: Any, decision: JevDecision, model: str, started_at: str, completed_at: str
) -> JevDecision:
    """Sign ``decision`` as a ``model_invocation`` receipt; set ``receipt_id``."""
    draft = {
        "kind": "model_invocation",
        "invocation_id": decision.invocation_id,
        "provider": "typesafe",
        "model_id": model,
        "model_version": decision.model_version,
        "provider_request_id": decision.request_id,
        "prompt_hash": decision.prompt_hash,
        "retrieval_set_hash": decision.retrieval_set_hash,
        "output_hash": decision.output_hash,
        "started_at": started_at,
        "completed_at": completed_at,
    }
    try:
        minted = client.post_mediation_receipt(draft)
    except (CueCruxError, httpx.HTTPError) as err:
        raise DecisionNotRecorded(
            f"Jev answered but no receipt was minted ({err}); "
            "the daemon needs CORECRUXD_STREAM_RECEIPTS=1",
            decision,
        ) from err
    return replace(decision, receipt_id=minted["receipt_id"])


def _store_decision(
    client: Any, decision: JevDecision, entity: str, model: str, **extra: Any
) -> JevDecision:
    """Store ``jev:<entity>`` / ``decision:<ref>`` linked to the receipt; set ``fact_id``."""
    record = {
        "answers": decision.answers,
        "model_id": model,
        "model_version": decision.model_version,
        "request_id": decision.request_id,
        "invocation_id": decision.invocation_id,
        "prompt_hash": decision.prompt_hash,
        "retrieval_set_hash": decision.retrieval_set_hash,
        "output_hash": decision.output_hash,
        **extra,
    }
    try:
        fact = client.store_fact(
            StoreFact(
                entity=f"jev:{entity}",
                key=f"decision:{decision.request_id or decision.invocation_id}",
                value=json.dumps(record, ensure_ascii=False, separators=(",", ":")),
                source_receipt=decision.receipt_id,
            )
        )
    except (CueCruxError, httpx.HTTPError) as err:
        raise DecisionNotRecorded(
            f"receipt {decision.receipt_id} minted but the decision fact was not stored ({err})",
            decision,
        ) from err
    return replace(decision, fact_id=fact.fact_id)


def decide(
    client: Any,
    questions: dict[str, dict[str, Any]],
    *,
    entity: str,
    token_budget: int,
    crux_query: str | None = None,
    untrusted: Any = None,
    jev: JevCaller | None = None,
    model: str = "jev-latest",
    store_state: bool = False,
) -> JevDecision:
    """Build state from Crux, ask Jev, sign a receipt, store the decision.

    ``client`` is a ``CueCruxClient``. ``questions`` is Jev's wire-format map,
    e.g. ``{"block": {"type": "noul", "instructions": "Block this command?"}}``.
    ``entity`` scopes retrieval and names the decision memory (``jev:<entity>``).
    ``token_budget`` is mandatory: it bounds the retrieved context.
    ``untrusted`` is any JSON value; it lands only in ``untrusted_input``.
    ``jev`` defaults to :func:`jev_http` with the environment's key.
    ``store_state=True`` also stores the exact request for :func:`replay` --
    ``untrusted`` included, in an ordinary (not private) fact; see the module
    docstring before turning it on.

    Retrieval and Jev errors propagate before anything is recorded. A receipt
    or fact failure after Jev answered raises :class:`DecisionNotRecorded`.
    """
    call = jev or jev_http()  # a missing key fails before any request
    bundle = fetch_bundle(client, entity=entity, query=crux_query, token_budget=token_budget)
    state: dict[str, Any] = {"trusted_context": [item.text for item in bundle.items]}
    if untrusted is not None:
        state["untrusted_input"] = untrusted
    retrieved = evidence(bundle.items)
    # Hash before the call: a state that cannot be canonicalised fails here,
    # not after Jev has been paid.
    prompt_hash = digest({"state": state, "questions": questions})

    started_at = _now()
    request = {"model": model, "state": state, "questions": questions}
    raw, request_id = call(request)
    completed_at = _now()
    answers, model_version = raw["answers"], raw["model"]

    decision = JevDecision(
        answers=answers,
        model_version=model_version,
        request_id=request_id,
        invocation_id=str(uuid.uuid4()),
        prompt_hash=prompt_hash,
        retrieval_set_hash=digest(retrieved),
        output_hash=digest({"model": model_version, "answers": answers}),
        state=state,
        bundle=bundle,
        raw=raw,
    )

    decision = _mint(client, decision, model, started_at, completed_at)
    ref = request_id or decision.invocation_id

    if store_state:
        try:
            client.store_fact(
                StoreFact(
                    entity=f"__jev__::{entity}",
                    key=f"request:{ref}",
                    value=json.dumps(request, ensure_ascii=False, separators=(",", ":")),
                    source_receipt=decision.receipt_id,
                )
            )
        except (CueCruxError, httpx.HTTPError) as err:
            raise DecisionNotRecorded(
                f"receipt {decision.receipt_id} minted but the replay request was not stored ({err})",
                decision,
            ) from err

    return _store_decision(
        client, decision, entity, model, retrieved=retrieved, retrieval_truncated=bundle.truncated
    )


class TamperedRequest(Exception):
    """A stored Jev request no longer matches the decision it was stored with."""


@dataclass(frozen=True)
class ReplayResult:
    """A stored request re-sent to Jev, next to the answers it first got."""

    old_answers: dict[str, Any]
    new_answers: dict[str, Any]
    old_model_version: str
    new_model_version: str
    changed: bool
    """``new_answers != old_answers``: any field, probabilities included."""
    request_id: str | None
    """The replay call's ``x-typesafe-request-id``."""
    raw: dict[str, Any]


def _latest_fact(client: Any, entity: str, key: str) -> Any:
    found = [f for f in client.get_facts_by_entity(entity) if f.key == key and not f.deleted]
    if not found:
        raise LookupError(f"no fact {entity} / {key}")
    return max(found, key=lambda f: f.version)


def replay(
    client: Any,
    entity: str,
    decision_key: str,
    *,
    jev: JevCaller | None = None,
    model: str | None = None,
) -> ReplayResult:
    """Re-send a decision's stored Jev request and compare the answers.

    ``decision_key`` is the decision fact's key (``decision:<request_id>``) in
    ``jev:<entity>``; the decision must have been made with
    ``store_state=True``. ``model`` replaces the model sent; by default the
    original is re-sent, so an alias such as ``jev-latest`` reaches whatever
    version it names today.

    Before Jev is called, the stored request must carry the decision's
    ``source_receipt`` and model, and ``{state, questions}`` must still hash
    to its ``prompt_hash``; otherwise :class:`TamperedRequest`. Replay writes
    nothing to Crux -- no receipt, no fact.
    """
    call = jev or jev_http()
    decision = _latest_fact(client, f"jev:{entity}", decision_key)
    stored = _latest_fact(
        client, f"__jev__::{entity}", "request:" + decision_key.removeprefix("decision:")
    )
    record, request = json.loads(decision.value), json.loads(stored.value)
    # ponytail: checked against the decision fact's copy of the receipt's
    # prompt_hash. The signed receipt body is only readable with a dataplane
    # (GET /v1/receipts/{id} is 501 without one); compare against it there.
    if (
        not decision.source_receipt
        or stored.source_receipt != decision.source_receipt
        or request.get("model") != record["model_id"]
        or digest({"state": request.get("state"), "questions": request.get("questions")})
        != record["prompt_hash"]
    ):
        raise TamperedRequest(
            f"__jev__::{entity} / {stored.key} does not match receipt {decision.source_receipt}"
        )

    raw, request_id = call({**request, "model": model} if model else request)
    return ReplayResult(
        old_answers=record["answers"],
        new_answers=raw["answers"],
        old_model_version=record["model_version"],
        new_model_version=raw["model"],
        changed=raw["answers"] != record["answers"],
        request_id=request_id,
        raw=raw,
    )
