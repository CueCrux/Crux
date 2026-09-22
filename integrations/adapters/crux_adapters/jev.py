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
came back -- as this process reported it: the daemon never talks to Jev, it
signs the hashes the caller sends. It does not show the decision was right, or
that anyone acted on it.

**Replay** is opt-in. ``decide(..., store_state=True)`` also stores the exact
Jev request as ``__jev__::<entity>`` / ``request:<request_id>``, linked to the
same receipt; :func:`replay` re-sends it (to a newer model if asked) after
checking it against the receipt's *signed* body -- see :func:`replay` for
exactly what is checked and what is still trusted. HTTP fact writes cannot be
private (``private=true`` is MCP-only), so that fact is an ordinary one: it
holds ``untrusted_input`` verbatim, anyone who can read the tenant's facts can
read it, and it is push-eligible on sync. The ``__`` namespace keeps it out of
undirected ``/v1/context`` recall, so a later :func:`decide` cannot pull the
stored untrusted input back in as ``trusted_context``.

Every hash is :func:`digest`: ``sha256`` over ``json.dumps(value,
ensure_ascii=False, separators=(",", ":"), allow_nan=False)`` encoded as UTF-8.
Key order is **preserved**, not sorted (so this is not RFC 8785 / JCS): key
order is part of what Jev reads -- a Choice's option order included -- so
reordering options is a different prompt and hashes differently. A text
evidence digest is therefore over the JSON string literal, quotes and escapes
included, not the raw text. The cookbook's "Canonical hashing" section says
what a non-Python verifier must reproduce.
"""

from __future__ import annotations

import email.utils
import hashlib
import json
import math
import os
import struct
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


def _json(value: Any) -> str:
    """The one serialiser: what is hashed, sent to Jev and stored. Key order kept."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def digest(value: Any) -> str:
    """``sha256:<hex>`` over compact UTF-8 JSON, key order preserved.

    Exactly ``sha256(json.dumps(value, ensure_ascii=False, separators=(",", ":"),
    allow_nan=False).encode("utf-8"))``. NaN and infinities raise ``ValueError``.
    """
    return "sha256:" + hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def evidence(items: Iterable[ContextItem]) -> list[list[str]]:
    """``[[item id, digest(text)], ...]`` in bundle order: the retrieval set.

    Fact ids are version-specific, and the text digest pins aux items (session
    state, dossier) whose ids are not. ``digest(text)`` hashes the JSON string
    literal (``"..."``, escapes included), not the raw text.
    """
    return [[item.id, digest(item.text)] for item in items]


_ATTEMPTS = 3
_MAX_WAIT = 60.0
# The request was not processed: rate-limited (429), overloaded (529),
# unavailable (503) or never fully received (408). A 500, 502 or 504 may come
# after Jev ran, and the call is paid, so those are not retried.
_RETRYABLE = frozenset({408, 429, 503, 529})


def _asked_wait(headers: httpx.Headers) -> float | None:
    """Seconds ``retry-after-ms`` / ``Retry-After`` ask for; ``None`` if absent or unusable.

    ``Retry-After`` is delay-seconds (ASCII digits) or an HTTP-date (a past date
    means now). Negative, non-finite and unparseable values are ignored.
    """
    try:
        wait = float(headers["retry-after-ms"]) / 1000
        if math.isfinite(wait) and wait >= 0:
            return wait
    except (KeyError, ValueError):
        pass
    value = headers.get("retry-after", "").strip()
    if value.isascii() and value.isdigit():
        return float(value)  # a huge value becomes inf, which is > 60: stop
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if when.tzinfo is None:  # "-0000": UTC, per RFC 5322
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())


def _retry_delay(resp: httpx.Response, attempt: int) -> float | None:
    """How long to wait before retrying ``resp``, or ``None``: do not retry.

    What the server asks, up to 60s; asked for longer, give up now rather than
    retry early. Asked nothing usable: 0.5s, 1s, ... capped at 8s.
    """
    wait = _asked_wait(resp.headers)
    if wait is None:
        return min(8.0, 0.5 * 2 ** (attempt - 1))
    return wait if wait <= _MAX_WAIT else None


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

    Only statuses that mean the request was not processed are retried -- 408,
    429, 503 and 529 -- up to three attempts in all, waiting what
    ``retry-after-ms`` / ``Retry-After`` asks (delay-seconds or HTTP-date) or
    else backing off exponentially. A server asking for more than 60s is not
    retried at all. 500, 502, 504, transport errors and timeouts are never
    retried: Jev may already have run the call, and billed it. Nor are other
    4xx. A final failure raises ``httpx.HTTPStatusError``.

    The body is sent as :func:`digest`'s serialisation, so the bytes on the
    wire are the bytes hashed and stored, whatever the ``httpx`` version.
    """
    # ponytail: no jitter. Inject a typesafe-sdk-backed caller for more.
    key = (api_key if api_key is not None else os.environ.get("TYPESAFE_API_KEY", "")).strip()
    if not key:
        raise ValueError("no Jev API key: pass api_key or set TYPESAFE_API_KEY")
    root = base_url or os.environ.get("TYPESAFE_BASE_URL") or "https://api.typesafe.ai"
    url = root.rstrip("/") + "/v1/systemone"

    def call(body: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
        attempt = 1
        while True:
            resp = (http or httpx).post(
                url,
                content=_json(body).encode("utf-8"),
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                timeout=30.0,
            )
            if attempt < _ATTEMPTS and resp.status_code in _RETRYABLE:
                delay = _retry_delay(resp, attempt)
                if delay is not None:
                    sleep(delay)
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
    client: Any,
    decision: JevDecision,
    model: str,
    started_at: str,
    completed_at: str,
    provider: str = "typesafe",
) -> JevDecision:
    """Hash Jev's output and sign ``decision`` as a ``model_invocation`` receipt.

    Sets ``output_hash`` and ``receipt_id``. Jev has answered, and been paid, by
    now, so answers that cannot be hashed (NaN, infinity) raise
    :class:`DecisionNotRecorded` with the answers kept, like any other failure
    to record.
    """
    try:
        output_hash = digest({"model": decision.model_version, "answers": decision.answers})
    except ValueError as err:
        raise DecisionNotRecorded(
            f"Jev answered but its answers cannot be hashed ({err}); nothing was recorded",
            decision,
        ) from err
    decision = replace(decision, output_hash=output_hash)
    draft = {
        "kind": "model_invocation",
        "invocation_id": decision.invocation_id,
        "provider": provider,
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
                value=_json(record),
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
    provider: str = "typesafe",
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
    docstring before turning it on. ``provider`` is the receipt's provider
    label: set it when ``jev`` is not TypeSafe's Jev (a stub, a proxy).

    Retrieval and Jev errors propagate before anything is recorded. After Jev
    answered, any failure to record -- receipt, fact, or answers that cannot
    be hashed -- raises :class:`DecisionNotRecorded`.
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
        output_hash="",  # set by _mint
        state=state,
        bundle=bundle,
        raw=raw,
    )

    decision = _mint(client, decision, model, started_at, completed_at, provider)
    ref = request_id or decision.invocation_id

    if store_state:
        try:
            client.store_fact(
                StoreFact(
                    entity=f"__jev__::{entity}",
                    key=f"request:{ref}",
                    value=_json(request),
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
    """A stored Jev request, or its decision, no longer matches the signed receipt."""


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


_CBOR_MAX_DEPTH = 16
_CBOR_FLOATS = {2: ">e", 4: ">f", 8: ">d"}


def _cbor_item(data: bytes, pos: int, depth: int) -> tuple[Any, int]:
    """The CBOR item at ``pos`` and the position after it. See :func:`_cbor_decode`."""
    if depth > _CBOR_MAX_DEPTH:
        raise ValueError("CBOR nested too deep")
    if pos >= len(data):
        raise ValueError("CBOR truncated")
    major, info = data[pos] >> 5, data[pos] & 0x1F
    pos += 1
    if info > 27:
        raise ValueError(f"CBOR additional info {info} (indefinite length or reserved)")
    size = 0 if info < 24 else 1 << (info - 24)
    if size > len(data) - pos:
        raise ValueError("CBOR truncated")
    raw, pos = data[pos : pos + size], pos + size
    arg = int.from_bytes(raw, "big") if size else info
    if major == 0:
        return arg, pos
    if major == 1:
        return -1 - arg, pos
    if major in (2, 3):
        if arg > len(data) - pos:
            raise ValueError("CBOR string runs past the end")
        chunk = data[pos : pos + arg]
        return (chunk if major == 2 else chunk.decode("utf-8")), pos + arg
    if major in (4, 5):
        if arg * (major - 3) > len(data) - pos:  # every item takes at least a byte
            raise ValueError("CBOR container runs past the end")
        if major == 4:
            items = []
            for _ in range(arg):
                item, pos = _cbor_item(data, pos, depth + 1)
                items.append(item)
            return items, pos
        out: dict[str, Any] = {}
        for _ in range(arg):
            key, pos = _cbor_item(data, pos, depth + 1)
            if not isinstance(key, str):
                raise ValueError("CBOR map key is not text")
            if key in out:
                raise ValueError(f"CBOR map repeats key {key!r}")
            out[key], pos = _cbor_item(data, pos, depth + 1)
        return out, pos
    if major == 7 and size == 0 and arg in (20, 21, 22):
        return (False, True, None)[arg - 20], pos
    if major == 7 and size in _CBOR_FLOATS:
        return struct.unpack(_CBOR_FLOATS[size], raw)[0], pos
    raise ValueError(f"CBOR major type {major} with additional info {info} not accepted")


def _cbor_decode(data: bytes) -> Any:
    """Strictly decode the CBOR subset the daemon signs receipt bodies in.

    Definite-length maps (text keys, none repeated), arrays, text and byte
    strings, integers, half/single/double floats, booleans and null: what
    ``ciborium`` emits for ``crates/corecrux-receipts`` bodies. The input is
    untrusted, so anything else -- tags, indefinite lengths, ``undefined`` and
    other simple values, a length past the end, invalid UTF-8, nesting deeper
    than 16, trailing bytes -- raises ``ValueError``.
    """
    value, end = _cbor_item(data, 0, 0)
    if end != len(data):
        raise ValueError("CBOR has trailing bytes")
    return value


_OBSERVATION_WINDOW = 1000  # the daemon's cap on GET /v1/observations/aggregate


def _blake3() -> Callable[[bytes], str]:
    """``bytes -> blake3 hex``, from the optional ``blake3`` package; fails closed without it."""
    try:
        from blake3 import blake3
    except ImportError as err:
        raise ImportError(
            "replay() hashes the signed receipt body with BLAKE3, which needs the "
            "'blake3' package: pip install 'cuecrux-adapters[jev-replay]'"
        ) from err
    return lambda data: blake3(data).hexdigest()


def _signed_body(client: Any, receipt_id: str, blake3: Callable[[bytes], str]) -> dict[str, Any]:
    """A ``model_invocation`` receipt's signed body, decoded, once the daemon verifies it.

    ``/verification`` checks the Ed25519 signature and reports ``payload_hash``,
    the BLAKE3 of the body bytes it checked. The bytes come from the mediation
    observation log (``GET /v1/observations/aggregate``), the place a daemon
    without a dataplane serves them. Anyone who can post session observations
    can add records to that listing, so every field of a listed record is
    untrusted: the body used is the one whose bytes hash, here, to the verified
    ``payload_hash``. Other records claiming ``receipt_id`` are ignored.
    """
    report = client.verify_receipt(receipt_id, tenant_id="local")
    if report.get("signature_valid") is not True or report.get("error_code") != "OK":
        raise TamperedRequest(f"receipt {receipt_id} does not verify ({report.get('error_code')})")
    verified = report.get("payload_hash")
    # ponytail: only the newest 1000 model_invocation observations are
    # searched (no by-id lookup without a dataplane); older receipts raise
    # LookupError. Add a receipt_id filter to the aggregate route if that bites.
    listing = client.aggregate_observations(kind="model_invocation", limit=_OBSERVATION_WINDOW)
    payloads = (o.get("payload") for o in listing.get("observations", []))
    found = [p for p in payloads if isinstance(p, dict) and p.get("receipt_id") == receipt_id]
    if not found:
        raise LookupError(
            f"receipt {receipt_id} is not among the daemon's newest "
            f"{_OBSERVATION_WINDOW} model_invocation observations"
        )
    raw = None
    for payload in found:
        try:
            data = bytes.fromhex(payload.get("body_cbor_hex"))
        except (TypeError, ValueError):
            continue
        if isinstance(verified, str) and blake3(data) == verified:
            raw = data
            break
    if raw is None:
        raise TamperedRequest(f"receipt {receipt_id}: no listed body hashes to the one verified")
    try:
        body = _cbor_decode(raw)
    except ValueError as err:
        raise TamperedRequest(f"receipt {receipt_id}: signed body is malformed ({err})") from err
    if (
        not isinstance(body, dict)
        or body.get("kind") != "model_invocation"
        or body.get("receipt_id") != receipt_id
    ):
        raise TamperedRequest(f"receipt {receipt_id}: signed body is not this model_invocation")
    return body


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

    Needs the ``blake3`` package (``pip install 'cuecrux-adapters[jev-replay]'``);
    without it replay raises ``ImportError`` before reading anything.

    Before Jev is called, both facts must name the same ``source_receipt``,
    the daemon must report that receipt's signature valid, and the receipt's
    **signed** body -- the listed bytes whose BLAKE3 is the payload hash the
    daemon verified, never the unsigned copies in the facts or next to the
    body -- must match:

    * ``prompt_hash``: the stored ``{state, questions}``, re-hashed;
    * ``model_id``: the stored request's ``model``;
    * ``provider_request_id`` (``invocation_id`` when Jev sent none): the
      ``<request_id>`` both fact keys carry;
    * ``output_hash``: the decision fact's ``{model_version, answers}``, so
      ``old_answers`` are the answers that were signed.

    Otherwise :class:`TamperedRequest`. A receipt older than the daemon's
    newest 1000 ``model_invocation`` observations raises ``LookupError``.
    Jev is sent exactly ``model``, ``state`` and ``questions``: any other key
    in the stored request is outside ``prompt_hash``, so it is dropped.

    So rewriting both facts consistently is caught. Still trusted: the
    daemon's own signature check, and anyone who can mint receipts on it
    (``POST /v1/mediation/receipts``), since the daemon signs whatever hashes
    it is sent. To take the daemon out of the signature check, verify the
    receipt offline (see the cookbook). Replay writes nothing to Crux -- no
    receipt, no fact.
    """
    call = jev or jev_http()
    blake3 = _blake3()
    ref = decision_key.removeprefix("decision:")
    decision = _latest_fact(client, f"jev:{entity}", decision_key)
    stored = _latest_fact(client, f"__jev__::{entity}", f"request:{ref}")
    receipt_id = decision.source_receipt
    if not receipt_id or stored.source_receipt != receipt_id:
        raise TamperedRequest(f"__jev__::{entity} / {stored.key} is not linked to receipt {receipt_id}")
    try:
        record, request = json.loads(decision.value), json.loads(stored.value)
        ours = {
            "prompt_hash": digest({"state": request.get("state"), "questions": request.get("questions")}),
            "model_id": request.get("model"),
            "provider_request_id": ref,
            "output_hash": digest({"model": record.get("model_version"), "answers": record.get("answers")}),
        }
    except (ValueError, AttributeError) as err:  # not JSON, not objects, or NaN
        raise TamperedRequest(f"jev:{entity} / {decision_key} cannot be checked ({err})") from err

    signed = _signed_body(client, receipt_id, blake3)
    signed = {**signed, "provider_request_id": signed.get("provider_request_id") or signed.get("invocation_id")}
    differ = [name for name, value in ours.items() if signed.get(name) != value]
    if differ:
        raise TamperedRequest(
            f"{', '.join(differ)} of jev:{entity} / {decision_key} differ from signed receipt {receipt_id}"
        )

    # Only what the receipt covers: prompt_hash is over state + questions.
    raw, request_id = call(
        {"model": model or request["model"], "state": request["state"], "questions": request["questions"]}
    )
    return ReplayResult(
        old_answers=record["answers"],
        new_answers=raw["answers"],
        old_model_version=record["model_version"],
        new_model_version=raw["model"],
        changed=raw["answers"] != record["answers"],
        request_id=request_id,
        raw=raw,
    )
