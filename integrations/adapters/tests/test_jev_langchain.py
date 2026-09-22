# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.

"""``JevReceiptHandler`` over real ``langchain-typesafe`` code, fake HTTP.

Skipped unless the ``jev-langchain`` extra is installed. Jev is an
``httpx2.MockTransport`` and the daemon is ``test_jev.FakeDaemon``, so the
hashes are checked against the bytes the classifier actually sent and got.
Nothing here reaches TypeSafe: the base URL is a closed loopback port.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import unittest
import uuid
import warnings
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "sdks" / "python" / "src"))

from crux_adapters.jev import DecisionNotRecorded, _cbor_decode, digest  # noqa: E402
from test_jev import FakeDaemon  # noqa: E402

try:
    import httpx2
    from langchain.agents import create_agent
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage, HumanMessage
    from langchain_core.tools import tool
    from langchain_typesafe import Choice, Score, TypeSafeClassifier
    from langchain_typesafe.client import TypeSafeInternalServerError
    from langchain_typesafe.experimental.middleware import (
        AutoModeMiddleware,
        ModelChoice,
        ModelRouterMiddleware,
    )

    from crux_adapters.jev_langchain import JevReceiptHandler
except ModuleNotFoundError:  # extra not installed
    JevReceiptHandler = None

NO_JEV = {"TYPESAFE_API_KEY": "test-key", "TYPESAFE_BASE_URL": "http://127.0.0.1:9"}


class FakeJev:
    """Answers every question by type; records what went over the wire."""

    def __init__(self, noul: float = 0.9, status: int = 200) -> None:
        self.noul, self.status = noul, status
        self.sent: list[dict] = []
        self.replies: list[dict] = []

    def __call__(self, request):
        body = json.loads(request.content)
        self.sent.append(body)
        if self.status != 200:
            return httpx2.Response(self.status, json={"detail": "boom"})
        answers = {}
        for name, q in body["questions"].items():
            if q["type"] == "noul":
                answers[name] = {"type": "noul", "noul": self.noul}
            elif q["type"] == "choice":
                labels = list(q["criteria"])
                answers[name] = {
                    "type": "choice",
                    "choice": labels[0],
                    "probabilities": {label: 1 / len(labels) for label in labels},
                    "confidence": 0.2,
                }
            else:
                answers[name] = {
                    "type": "score",
                    "score": 1.25,
                    "legend": {str(i): c for i, c in enumerate(q["criteria"])},
                    "probabilities": {str(i): 1 / len(q["criteria"]) for i in range(len(q["criteria"]))},
                    "confidence": 0.4,
                }
        reply = {"model": "jev-1.13.0", "answers": answers, "usage": {"input_tokens": 9, "output_tokens": 2}}
        self.replies.append(reply)
        return httpx2.Response(
            200, json=reply, headers={"x-typesafe-request-id": f"req_{len(self.sent)}"}
        )

    def classifier(self) -> TypeSafeClassifier:
        transport = httpx2.MockTransport(self)
        with mock.patch.dict(os.environ, NO_JEV):
            return TypeSafeClassifier(
                client=httpx2.Client(transport=transport),
                async_client=httpx2.AsyncClient(transport=transport),
            )


def classifier_request() -> dict:
    """Message state and a Score question: the two places wire form differs from input."""
    return {
        "state": {"conversation": [HumanMessage("It failed three times. Fix it now.")]},
        "questions": {
            "team": Choice(instructions="Who handles it?", criteria={"billing": "b", "tech": "t"}),
            "anger": Score(instructions="How angry?", criteria=["calm", "cross", "furious"]),
        },
    }


def run_agent(jev: FakeJev, daemon: FakeDaemon, use_async: bool = False):
    """A real ``create_agent`` run: router picks the model, Auto Mode vets ``delete_file``."""
    executed: list[str] = []

    @tool
    def delete_file(path: str) -> str:
        """Delete a file."""
        executed.append(path)
        return "deleted"

    class Model(GenericFakeChatModel):
        def bind_tools(self, tools, **kwargs):
            return self

    model = Model(
        messages=iter(
            [
                AIMessage("", tool_calls=[{"name": "delete_file", "args": {"path": "/x"}, "id": "c1"}]),
                AIMessage("done"),
            ]
        )
    )
    with mock.patch.dict(os.environ, NO_JEV):
        router = ModelRouterMiddleware(
            choices={"fast": ModelChoice(model=model, criteria="Simple tasks.")},
            instructions="Choose the cheapest model.",
        )
        auto = AutoModeMiddleware(tools=[delete_file])
    # Only the HTTP is redirected to the fake; the middleware is otherwise untouched.
    router.classifier = auto.classifier = jev.classifier()
    agent = create_agent(model, tools=[delete_file], middleware=[router, auto])
    handler = JevReceiptHandler(daemon.client(), entity="agent:build-bot")
    inputs, config = {"messages": [HumanMessage("please delete /x")]}, {"callbacks": [handler]}
    out = asyncio.run(agent.ainvoke(inputs, config)) if use_async else agent.invoke(inputs, config)
    return out, executed, handler


@unittest.skipIf(JevReceiptHandler is None, "langchain-typesafe[experimental] not installed")
class MiddlewareDecisions(unittest.TestCase):
    def test_each_middleware_decision_gets_a_receipt_and_a_fact(self) -> None:
        for use_async in (False, True):  # before_agent/wrap_tool_call and their a* twins
            with self.subTest(use_async=use_async):
                if use_async and sys.version_info < (3, 11):
                    # The middleware calls ainvoke() with no config, and 3.10
                    # asyncio cannot carry LangChain's context: no callbacks.
                    self.skipTest("async callback propagation needs Python 3.11+")
                self.check_agent_run(use_async)

    def check_agent_run(self, use_async: bool) -> None:
        jev, daemon = FakeJev(noul=0.9), FakeDaemon()
        out, executed, handler = run_agent(jev, daemon, use_async)

        self.assertEqual(executed, [])  # Auto Mode blocked it
        self.assertEqual(out["messages"][2].status, "error")
        self.assertEqual(handler._pending, {})

        drafts = [json.loads(r.content) for r in daemon.sent("POST", "/v1/mediation/receipts")]
        facts = [json.loads(r.content) for r in daemon.sent("PUT", "/v1/facts")]
        # One per Jev call (router, then Auto Mode); agent/model/tool runs ignored.
        self.assertEqual(len(jev.sent), 2)
        self.assertEqual((len(drafts), len(facts)), (2, 2))
        self.assertEqual([list(s["questions"]) for s in jev.sent], [["model_route"], ["is_risky"]])

        for n, (sent, reply, draft, fact) in enumerate(zip(jev.sent, jev.replies, drafts, facts), 1):
            with self.subTest(call=n):
                # Hashes recomputed from the wire, not from what the handler saw.
                prompt = digest({"state": sent["state"], "questions": sent["questions"]})
                output = digest({"model": reply["model"], "answers": reply["answers"]})
                self.assertEqual(draft["prompt_hash"], prompt)
                self.assertEqual(draft["output_hash"], output)
                self.assertEqual(
                    {k: draft[k] for k in ("kind", "provider", "model_id", "model_version",
                                            "provider_request_id", "retrieval_set_hash")},
                    {"kind": "model_invocation", "provider": "typesafe", "model_id": "jev-latest",
                     "model_version": "jev-1.13.0", "provider_request_id": f"req_{n}",
                     "retrieval_set_hash": None},  # Crux did not build this state
                )
                uuid.UUID(draft["invocation_id"])  # the LangChain run id
                self.assertLessEqual(draft["started_at"], draft["completed_at"])

                self.assertEqual(
                    (fact["entity"], fact["key"], fact["source_receipt"]),
                    ("jev:agent:build-bot", f"decision:req_{n}", "r_test"),
                )
                record = json.loads(fact["value"])
                self.assertIsNone(record["retrieval_set_hash"])
                self.assertNotIn("retrieved", record)
                self.assertEqual(record["answers"], reply["answers"])
                self.assertEqual(record["invocation_id"], draft["invocation_id"])
                self.assertEqual(
                    digest({"model": record["model_version"], "answers": record["answers"]}),
                    draft["output_hash"],
                )
        self.assertNotEqual(drafts[0]["prompt_hash"], drafts[1]["prompt_hash"])

    def test_unrecorded_decision_fails_closed(self) -> None:
        # Jev says "safe", but the receipt cannot be minted: the tool must not run.
        jev, daemon = FakeJev(noul=0.1), FakeDaemon(receipt_status=422)
        with self.assertRaises(DecisionNotRecorded) as caught:
            run_agent(jev, daemon)
        self.assertEqual(caught.exception.decision.request_id, "req_1")
        self.assertIsNone(caught.exception.decision.receipt_id)
        self.assertEqual(daemon.sent("PUT", "/v1/facts"), [])

    def test_positive_control_safe_call_runs_when_recorded(self) -> None:
        # Same setup, working daemon: the tool does run, so the test above
        # failed closed because of the record, not the fake.
        jev, daemon = FakeJev(noul=0.1), FakeDaemon()
        _, executed, _ = run_agent(jev, daemon)
        self.assertEqual(executed, ["/x"])
        self.assertEqual(len(daemon.sent("POST", "/v1/mediation/receipts")), 2)


@unittest.skipIf(JevReceiptHandler is None, "langchain-typesafe[experimental] not installed")
class ClassifierDecisions(unittest.TestCase):
    def check(self, jev: FakeJev, daemon: FakeDaemon) -> None:
        (sent,), (reply,) = jev.sent, jev.replies
        (draft,) = [json.loads(r.content) for r in daemon.sent("POST", "/v1/mediation/receipts")]
        self.assertEqual(sent["state"]["conversation"][0]["role"], "user")  # message serialised
        self.assertEqual(draft["prompt_hash"], digest({"state": sent["state"], "questions": sent["questions"]}))
        # Score keys come back as ints from pydantic; the hash is over the wire's strings.
        self.assertEqual(draft["output_hash"], digest({"model": reply["model"], "answers": reply["answers"]}))

    def test_direct_invoke(self) -> None:
        jev, daemon = FakeJev(), FakeDaemon()
        handler = JevReceiptHandler(daemon.client(), entity="ticket:7")
        jev.classifier().invoke(classifier_request(), config={"callbacks": [handler]})
        self.check(jev, daemon)

    def test_async_invoke(self) -> None:
        jev, daemon = FakeJev(), FakeDaemon()
        handler = JevReceiptHandler(daemon.client(), entity="ticket:7")
        asyncio.run(jev.classifier().ainvoke(classifier_request(), config={"callbacks": [handler]}))
        self.check(jev, daemon)

    def test_malformed_daemon_reply_fails_closed(self) -> None:
        # A 200 that is not a receipt / fact is a failure to record, not a
        # KeyError: DecisionNotRecorded, answers kept, raised out of the call.
        import httpx

        for route, receipt_id in (("receipt", None), ("fact", "r_test")):
            with self.subTest(route=route):
                jev, daemon = FakeJev(), FakeDaemon()
                setattr(daemon, f"{route}_reply", httpx.Response(200, json={}))
                handler = JevReceiptHandler(daemon.client(), entity="ticket:7")
                with self.assertRaises(DecisionNotRecorded) as caught:
                    jev.classifier().invoke(classifier_request(), config={"callbacks": [handler]})
                self.assertIsInstance(caught.exception.__cause__, KeyError)
                self.assertEqual(caught.exception.decision.answers, jev.replies[0]["answers"])
                self.assertEqual(caught.exception.decision.receipt_id, receipt_id)

    def test_jev_failure_records_nothing(self) -> None:
        jev, daemon = FakeJev(status=500), FakeDaemon()
        handler = JevReceiptHandler(daemon.client(), entity="ticket:7")
        with self.assertRaises(TypeSafeInternalServerError):
            jev.classifier().invoke(classifier_request(), config={"callbacks": [handler]})
        self.assertEqual(daemon.requests, [])
        self.assertEqual(handler._pending, {})


@unittest.skipIf(JevReceiptHandler is None, "langchain-typesafe[experimental] not installed")
class PythonVersionWarning(unittest.TestCase):
    def test_warns_on_python_310_only(self):
        daemon = FakeDaemon()
        with mock.patch.object(sys, "version_info", (3, 10, 20)):
            with self.assertWarns(RuntimeWarning):
                JevReceiptHandler(daemon.client(), entity="e")
        with mock.patch.object(sys, "version_info", (3, 12, 0)):
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                JevReceiptHandler(daemon.client(), entity="e")


@unittest.skipIf(JevReceiptHandler is None, "langchain-typesafe[experimental] not installed")
@unittest.skipUnless(os.environ.get("CRUX_FIXTURE_URL"), "CRUX_FIXTURE_URL not set")
class FixtureDaemon(unittest.TestCase):
    def test_signed_body_has_no_retrieval_set_hash(self) -> None:
        from cuecrux_client import CueCruxClient

        token_file = os.environ.get("CRUX_TOKEN_FILE")
        token = Path(token_file).read_text().strip() if token_file else None
        client = CueCruxClient(os.environ["CRUX_FIXTURE_URL"], token=token)
        self.addCleanup(client.close)
        entity = f"test-jev-langchain:{uuid.uuid4().hex[:8]}"
        jev = FakeJev()
        jev.classifier().invoke(
            classifier_request(), config={"callbacks": [JevReceiptHandler(client, entity=entity)]}
        )

        (fact,) = client.get_facts_by_entity(f"jev:{entity}")
        record = json.loads(fact.value)
        self.assertEqual(client.verify_receipt(fact.source_receipt, tenant_id="local")["error_code"], "OK")
        observations = client.aggregate_observations(kind="model_invocation", limit=1000)["observations"]
        (body,) = [
            _cbor_decode(bytes.fromhex(o["payload"]["body_cbor_hex"]))
            for o in observations
            if o["payload"].get("receipt_id") == fact.source_receipt
        ]
        self.assertEqual(  # the signed body, decoded: the right one, and no retrieval claim
            (body["prompt_hash"], body["output_hash"], body["provider"]),
            (record["prompt_hash"], record["output_hash"], "typesafe"),
        )
        self.assertNotIn("retrieval_set_hash", body)


if __name__ == "__main__":
    unittest.main()
