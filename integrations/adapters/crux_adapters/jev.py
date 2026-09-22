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

Every hash is :func:`digest`: sha256 over compact UTF-8 JSON with key order
**preserved**. Key order is part of what Jev reads -- a Choice's option order
included -- so reordering options is a different prompt and hashes differently.
"""

from __future__ import annotations

import hashlib
import json
import os
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
    "decide",
    "digest",
    "evidence",
    "jev_http",
]

#: A Jev caller: request body in, ``(response JSON, request id)`` out. Wrap the
#: official ``typesafe-sdk`` client in one of these to use its retry policy.
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


def jev_http(
    api_key: str | None = None,
    *,
    base_url: str | None = None,
    http: httpx.Client | None = None,
) -> JevCaller:
    """A :data:`JevCaller` over the one HTTP endpoint, using ``httpx``.

    ``api_key`` and ``base_url`` fall back to ``TYPESAFE_API_KEY`` and
    ``TYPESAFE_BASE_URL``, the official SDK's variables. The request id comes
    from the ``x-typesafe-request-id`` response header.
    """
    # ponytail: no retries. 429/529 raise httpx.HTTPStatusError; inject a
    # typesafe-sdk-backed caller for its backoff policy.
    key = (api_key if api_key is not None else os.environ.get("TYPESAFE_API_KEY", "")).strip()
    if not key:
        raise ValueError("no Jev API key: pass api_key or set TYPESAFE_API_KEY")
    root = base_url or os.environ.get("TYPESAFE_BASE_URL") or "https://api.typesafe.ai"
    url = root.rstrip("/") + "/v1/systemone"

    def call(body: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
        resp = (http or httpx).post(
            url, json=body, headers={"Authorization": f"Bearer {key}"}, timeout=30.0
        )
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
    retrieval_set_hash: str
    output_hash: str
    state: Any
    """The exact state sent, for replay against a later model version."""
    bundle: ContextBundle
    """The retrieved context. ``bundle.truncated`` means the budget cut it."""
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
) -> JevDecision:
    """Build state from Crux, ask Jev, sign a receipt, store the decision.

    ``client`` is a ``CueCruxClient``. ``questions`` is Jev's wire-format map,
    e.g. ``{"block": {"type": "noul", "instructions": "Block this command?"}}``.
    ``entity`` scopes retrieval and names the decision memory (``jev:<entity>``).
    ``token_budget`` is mandatory: it bounds the retrieved context.
    ``untrusted`` is any JSON value; it lands only in ``untrusted_input``.
    ``jev`` defaults to :func:`jev_http` with the environment's key.

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
    raw, request_id = call({"model": model, "state": state, "questions": questions})
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

    draft = {
        "kind": "model_invocation",
        "invocation_id": decision.invocation_id,
        "provider": "typesafe",
        "model_id": model,
        "model_version": model_version,
        "provider_request_id": request_id,
        "prompt_hash": decision.prompt_hash,
        "retrieval_set_hash": decision.retrieval_set_hash,
        "output_hash": decision.output_hash,
        "started_at": started_at,
        "completed_at": completed_at,
    }
    try:
        # The SDK has no public mediation-receipt method yet; _request keeps
        # its auth header and CueCruxError mapping.
        minted = client._request("POST", "/v1/mediation/receipts", json=draft)
    except (CueCruxError, httpx.HTTPError) as err:
        raise DecisionNotRecorded(
            f"Jev answered but no receipt was minted ({err}); "
            "the daemon needs CORECRUXD_STREAM_RECEIPTS=1",
            decision,
        ) from err
    decision = replace(decision, receipt_id=minted["receipt_id"])

    record = {
        "answers": answers,
        "model_id": model,
        "model_version": model_version,
        "request_id": request_id,
        "invocation_id": decision.invocation_id,
        "prompt_hash": decision.prompt_hash,
        "retrieval_set_hash": decision.retrieval_set_hash,
        "output_hash": decision.output_hash,
        "retrieved": retrieved,
        "retrieval_truncated": bundle.truncated,
    }
    try:
        fact = client.store_fact(
            StoreFact(
                entity=f"jev:{entity}",
                key=f"decision:{request_id or decision.invocation_id}",
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
