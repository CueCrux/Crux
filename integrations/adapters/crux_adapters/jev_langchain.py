# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.

"""Receipts for Jev decisions made through ``langchain-typesafe``.

``TypeSafeClassifier`` -- and ``ModelRouterMiddleware`` / ``AutoModeMiddleware``,
which each build one -- runs as a LangChain ``Runnable`` tagged
``ls_provider="typesafe"``, so a callback handler passed in the run config sees
every Jev call: the request on ``on_chain_start``, the ``ClassifierResponse``
(model version, ``request_id``) on ``on_chain_end``. :class:`JevReceiptHandler`
records each one as :func:`~.jev.decide` does -- a signed ``model_invocation``
receipt plus a ``jev:<entity>`` / ``decision:<request_id>`` fact:

    handler = JevReceiptHandler(crux_client, entity="agent:build-bot")
    agent.invoke(inputs, config={"callbacks": [handler]})

Here LangChain built the state, not Crux: ``retrieval_set_hash`` is ``None`` in
both the receipt draft (so the signed body has none) and the fact, and the fact
carries no ``retrieved`` list. The receipt claims no Crux retrieval.

``prompt_hash`` is over ``{state, questions}`` as the classifier puts them on
the wire (messages converted to role/content JSON); ``output_hash`` is over
``{model, answers}`` as the classifier parsed them. As with :func:`~.jev.decide`,
a record that fails raises :class:`~.jev.DecisionNotRecorded` out of the
classifier call (``raise_error``), so ``AutoModeMiddleware`` fails closed.

On Python 3.10, async agent runs do not reach this handler for middleware
calls (they ``ainvoke`` the classifier with no config), so those go unrecorded.

Install with the extra::

    pip install 'cuecrux-adapters[jev-langchain]'
"""

from __future__ import annotations

import sys
import warnings
from typing import Any
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler

# ponytail: the classifier's own state serialiser, so prompt_hash is over the
# wire state by construction. Private name, pinned by the extra's version range;
# tests/test_jev_langchain.py fails if it stops matching the wire.
from langchain_typesafe._state import serialize_state

from .jev import JevDecision, _mint, _now, _store_decision, digest

__all__ = ["JevReceiptHandler"]


class JevReceiptHandler(BaseCallbackHandler):
    """Record each ``langchain-typesafe`` Jev call as a receipt and a fact.

    ``client`` is a ``CueCruxClient`` (daemon flag
    ``CORECRUXD_STREAM_RECEIPTS=1``); ``entity`` names the decision memory
    ``jev:<entity>``. The receipt's ``invocation_id`` is the LangChain run id,
    so a trace and its receipt share an id. Other runs are ignored.
    """

    raise_error = True
    """An unrecorded decision fails the call, as in :func:`~.jev.decide`. Set
    ``False`` to log recording failures and carry on."""

    def __init__(self, client: Any, *, entity: str) -> None:
        if sys.version_info < (3, 11):
            warnings.warn(
                "JevReceiptHandler on Python 3.10: async agent runs (middleware "
                "ainvoke without config) do not reach callbacks, so those Jev "
                "decisions are NOT recorded. Use Python >=3.11 or sync runs.",
                RuntimeWarning,
                stacklevel=2,
            )
        self.client = client
        self.entity = entity
        self._pending: dict[UUID, tuple[str, Any, str, str]] = {}

    def on_chain_start(
        self,
        serialized: dict[str, Any] | None,
        inputs: Any,
        *,
        run_id: UUID,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        if (metadata or {}).get("ls_provider") != "typesafe":
            return
        state = serialize_state(inputs["state"])
        questions = {  # what TypeSafeClassifier sends
            name: q.model_dump(mode="json", exclude_none=True)
            for name, q in inputs["questions"].items()
        }
        prompt_hash = digest({"state": state, "questions": questions})
        self._pending[run_id] = (metadata["ls_model_name"], state, prompt_hash, _now())

    def on_chain_error(self, error: BaseException, *, run_id: UUID, **kwargs: Any) -> None:
        self._pending.pop(run_id, None)  # Jev did not answer: nothing to record

    def on_chain_end(self, outputs: Any, *, run_id: UUID, **kwargs: Any) -> None:
        pending = self._pending.pop(run_id, None)
        if pending is None:
            return
        model, state, prompt_hash, started_at = pending
        raw = outputs.model_dump(mode="json")
        decision = JevDecision(
            answers=raw["answers"],
            model_version=raw["model"],
            request_id=raw["request_id"],
            invocation_id=str(run_id),
            prompt_hash=prompt_hash,
            retrieval_set_hash=None,  # LangChain built the state, not Crux
            output_hash=digest({"model": raw["model"], "answers": raw["answers"]}),
            state=state,
            bundle=None,
            raw=raw,
        )
        decision = _mint(self.client, decision, model, started_at, _now())
        _store_decision(self.client, decision, self.entity, model)
