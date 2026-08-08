# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.

"""Wire-shape tests for the CueCrux Python SDK.

These run against a real local HTTP server (stdlib ``http.server``) rather
than a patched transport, so the assertions cover what actually goes on the
socket: method, path, query string and JSON body. Every route string here was
read off the daemon's own route manifest (``crates/corecruxd/src/http/openapi.rs``)
at the commit these tests landed on.

For the round-trip against a live daemon see ``sdks/live-smoke.sh``.
"""

from __future__ import annotations

import asyncio
import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cuecrux_client.client import (  # noqa: E402
    AsyncCueCruxClient,
    CueCruxClient,
    _sse_event,
)
from cuecrux_client.errors import CueCruxError  # noqa: E402

# Requests the stub server saw, oldest first.
CALLS: list[dict[str, object]] = []

SSE_BODY = (
    ": keep-alive\n"
    "\n"
    "event: fact.stored\n"
    'data: {"type":"fact.stored","fact_id":"f_1","entity":"e","key":"k"}\n'
    "\n"
    ": keep-alive\n"
    "\n"
    "event: session.stored\n"
    'data: {"type":"session.stored","session_id":"s_1"}\n'
    "\n"
)


class _Handler(BaseHTTPRequestHandler):
    """Records every request, then answers by path."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:  # silence the test run
        pass

    def _record(self, method: str) -> dict[str, object]:
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        call: dict[str, object] = {
            "method": method,
            "path": parsed.path,
            "query": parsed.query,
            "body": json.loads(raw) if raw else None,
        }
        CALLS.append(call)
        return call

    def _respond(self, call: dict[str, object]) -> None:
        path = str(call["path"])
        query = str(call["query"])

        if path == "/v1/events/stream":
            body = SSE_BODY.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/v1/extensions/missing":
            body = json.dumps(
                {"type": "about:blank", "title": "Not Found", "status": 404, "detail": "no such extension"}
            ).encode()
            self.send_response(404)
            self.send_header("Content-Type", "application/problem+json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/v1/context" and "render=markdown" in query:
            body = b"# Crux context\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/markdown; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        body = json.dumps({"schema": "stub.v1"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._respond(self._record("GET"))

    def do_POST(self) -> None:
        self._respond(self._record("POST"))

    def do_PUT(self) -> None:
        self._respond(self._record("PUT"))

    def do_DELETE(self) -> None:
        self._respond(self._record("DELETE"))


class WireShapeTest(unittest.TestCase):
    server: ThreadingHTTPServer
    base_url: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        CALLS.clear()
        self.client = CueCruxClient(self.base_url)
        self.addCleanup(self.client.close)

    @property
    def last(self) -> dict[str, object]:
        self.assertTrue(CALLS, "no request reached the server")
        return CALLS[-1]

    def assertCall(self, method: str, path: str) -> dict[str, object]:
        self.assertEqual(self.last["method"], method)
        self.assertEqual(self.last["path"], path)
        return self.last

    # -- context --

    def test_context_sends_only_the_options_that_were_set(self) -> None:
        self.client.context(entity="execplan:demo", token_budget=500)
        call = self.assertCall("GET", "/v1/context")
        # session_id and query were never passed; they must not appear at all.
        self.assertEqual(sorted(str(call["query"]).split("&")), ["entity=execplan%3Ademo", "token_budget=500"])

    def test_context_with_no_options_sends_no_query_string(self) -> None:
        self.client.context()
        self.assertEqual(self.assertCall("GET", "/v1/context")["query"], "")

    def test_post_context_puts_options_in_the_body(self) -> None:
        self.client.post_context(query="what changed", token_budget=2000)
        call = self.assertCall("POST", "/v1/context")
        self.assertEqual(call["body"], {"query": "what changed", "token_budget": 2000})

    def test_context_markdown_returns_text_not_json(self) -> None:
        out = self.client.context_markdown(entity="e")
        self.assertEqual(out, "# Crux context\n")
        self.assertIn("render=markdown", str(self.assertCall("GET", "/v1/context")["query"]))

    def test_context_messages_requests_the_openai_render(self) -> None:
        self.client.context_messages()
        self.assertIn("render=openai_messages", str(self.assertCall("GET", "/v1/context")["query"]))

    # -- review --

    def test_extract_memory_posts_text_and_omits_unset_fields(self) -> None:
        self.client.extract_memory("we chose postgres", profile="comprehensive")
        call = self.assertCall("POST", "/v1/memory/extract")
        self.assertEqual(call["body"], {"text": "we chose postgres", "profile": "comprehensive"})

    def test_list_candidates_filters_by_status(self) -> None:
        self.client.list_candidates(status="candidate")
        self.assertEqual(self.assertCall("GET", "/v1/memory/candidates")["query"], "status=candidate")

    def test_list_candidates_without_status_sends_no_filter(self) -> None:
        self.client.list_candidates()
        self.assertEqual(self.assertCall("GET", "/v1/memory/candidates")["query"], "")

    def test_promote_candidate_carries_the_auto_threshold(self) -> None:
        self.client.promote_candidate("cand_1", auto_threshold=0.9)
        call = self.assertCall("POST", "/v1/memory/candidates/cand_1/promote")
        self.assertEqual(call["body"], {"auto_threshold": 0.9})

    def test_promote_candidate_defaults_to_an_explicit_review(self) -> None:
        # No auto_threshold: the daemon must not read this as a score-gated
        # promotion, so the field has to be absent rather than null.
        self.client.promote_candidate("cand_1", reviewer="myles")
        self.assertEqual(self.last["body"], {"reviewer": "myles"})

    def test_reject_candidate_requires_a_reason(self) -> None:
        self.client.reject_candidate("cand_1", "wrong entity")
        call = self.assertCall("POST", "/v1/memory/candidates/cand_1/reject")
        self.assertEqual(call["body"], {"reason": "wrong entity"})

    def test_review_contradictions_and_queue_are_distinct_routes(self) -> None:
        self.client.review_contradictions(limit=10)
        self.assertEqual(self.assertCall("GET", "/v1/console/review/contradictions")["query"], "limit=10")
        self.client.review_queue()
        self.assertEqual(self.assertCall("GET", "/v1/console/review/queue")["query"], "")

    def test_apply_expiries_wraps_ids_in_fact_ids(self) -> None:
        self.client.apply_expiries(["f_1", "f_2"])
        call = self.assertCall("POST", "/v1/console/review/expiries")
        self.assertEqual(call["body"], {"fact_ids": ["f_1", "f_2"]})

    # -- consolidation --

    def test_consolidate_posts_the_canonical_merge(self) -> None:
        self.client.consolidate("e", "k", "canonical", ["f_1", "f_2"], protected_confidence_floor=0.95)
        call = self.assertCall("POST", "/v1/console/review/consolidations")
        self.assertEqual(
            call["body"],
            {
                # Sent explicitly: the daemon has no serde default for this
                # field, so an absent key is a 422 while a blank one gets
                # `console-<uuid>`.
                "consolidation_id": "",
                "entity": "e",
                "key": "k",
                "canonical_value": "canonical",
                "target_fact_ids": ["f_1", "f_2"],
                "protected_confidence_floor": 0.95,
            },
        )

    def test_consolidate_honours_an_explicit_consolidation_id(self) -> None:
        self.client.consolidate("e", "k", "v", ["f_1"], consolidation_id="run-7")
        call = self.assertCall("POST", "/v1/console/review/consolidations")
        self.assertEqual(call["body"]["consolidation_id"], "run-7")

    def test_undo_consolidation_posts_to_the_undo_route(self) -> None:
        self.client.undo_consolidation("f_canon", entity="e")
        call = self.assertCall("POST", "/v1/console/review/consolidations/undo")
        self.assertEqual(call["body"], {"canonical_fact_id": "f_canon", "entity": "e"})

    # -- ingest --

    def test_local_ingest_posts_documents(self) -> None:
        docs = [{"doc_id": "d1", "chunks": [{"chunk_id": "c1", "text": "hello"}]}]
        self.client.local_ingest("tenant", "corpus", docs)
        call = self.assertCall("POST", "/v1/local/ingest")
        self.assertEqual(call["body"], {"tenant_id": "tenant", "corpus_id": "corpus", "documents": docs})

    def test_import_memory_pack_sends_dry_run(self) -> None:
        self.client.import_memory_pack("tenant", {"manifest": {}}, dry_run=True)
        call = self.assertCall("POST", "/v1/memory/import")
        self.assertEqual(call["body"], {"tenant_id": "tenant", "pack": {"manifest": {}}, "dry_run": True})

    # -- extensions --

    def test_extension_routes(self) -> None:
        self.client.list_extensions()
        self.assertCall("GET", "/v1/extensions")

        self.client.register_extension({"id": "x"})
        self.assertEqual(self.assertCall("POST", "/v1/extensions/register")["body"], {"manifest": {"id": "x"}})

        self.client.list_registry_entries()
        self.assertCall("GET", "/v1/extensions/registry")

        self.client.install_from_registry("ext-1")
        self.assertEqual(
            self.assertCall("POST", "/v1/extensions/install-from-registry")["body"], {"id": "ext-1"}
        )

        self.client.list_trusted_keys()
        self.assertCall("GET", "/v1/extensions/keys")

        self.client.add_trusted_key("fpr1", "abcd", "community")
        self.assertEqual(
            self.assertCall("POST", "/v1/extensions/keys")["body"],
            {"passport_fpr": "fpr1", "public_key_hex": "abcd", "trust_tier": "community"},
        )

        self.client.delete_trusted_key("fpr1")
        self.assertCall("DELETE", "/v1/extensions/keys/fpr1")

        self.client.list_grants("ext-1")
        self.assertCall("GET", "/v1/extensions/ext-1/grants")

        self.client.issue_grant("ext-1", "fpr1", allowed_tool_names=["t"])
        self.assertEqual(
            self.assertCall("POST", "/v1/extensions/ext-1/grants")["body"],
            {"passport_fpr": "fpr1", "allowed_tool_names": ["t"]},
        )

        self.client.revoke_grant("ext-1", "fpr1")
        self.assertCall("DELETE", "/v1/extensions/ext-1/grants/fpr1")

    def test_invoke_tool_defaults_args_to_an_empty_object(self) -> None:
        self.client.invoke_extension_tool("ext-1", "search")
        call = self.assertCall("POST", "/v1/extensions/ext-1/tools/search/invoke")
        self.assertEqual(call["body"], {"args": {}})

    def test_get_extension_returns_none_on_404(self) -> None:
        self.assertIsNone(self.client.get_extension("missing"))

    def test_delete_extension_returns_false_on_404(self) -> None:
        self.assertFalse(self.client.delete_extension("missing"))

    def test_other_errors_still_raise(self) -> None:
        with self.assertRaises(CueCruxError) as ctx:
            self.client._request("GET", "/v1/extensions/missing")
        self.assertEqual(ctx.exception.status_code, 404)

    # -- events --

    def test_subscribe_events_skips_keepalives_and_decodes_data(self) -> None:
        events = list(self.client.subscribe_events(types=["fact.stored", "session.stored"]))
        self.assertEqual([e["type"] for e in events], ["fact.stored", "session.stored"])
        self.assertEqual(events[0]["fact_id"], "f_1")
        self.assertEqual(self.assertCall("GET", "/v1/events/stream")["query"], "types=fact.stored%2Csession.stored")

    def test_subscribe_events_without_types_sends_no_filter(self) -> None:
        # An explicit blank `types=` means "match nothing" daemon-side, so an
        # unfiltered subscription must omit the parameter entirely.
        list(self.client.subscribe_events())
        self.assertEqual(self.assertCall("GET", "/v1/events/stream")["query"], "")

    def test_sse_parser_ignores_comments_and_bad_json(self) -> None:
        self.assertIsNone(_sse_event(": keep-alive"))
        self.assertIsNone(_sse_event("event: fact.stored"))
        self.assertIsNone(_sse_event("data: not json"))
        self.assertEqual(_sse_event('data: {"a":1}'), {"a": 1})
        # A multi-line data payload rejoins with newlines per the SSE spec.
        self.assertEqual(_sse_event('data: {"a":\ndata: 1}'), {"a": 1})


class AsyncParityTest(unittest.TestCase):
    """The async client must speak the same wire as the sync one."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        CALLS.clear()

    def test_async_client_mirrors_the_sync_surface(self) -> None:
        async def run() -> list[dict[str, object]]:
            async with AsyncCueCruxClient(self.base_url) as client:
                await client.context(entity="e", token_budget=500)
                await client.post_context(query="q")
                self.assertEqual(await client.context_markdown(), "# Crux context\n")
                await client.extract_memory("text")
                await client.list_candidates(status="promoted")
                await client.promote_candidate("c1", auto_threshold=0.9)
                await client.reject_candidate("c1", "nope")
                await client.review_contradictions(limit=5)
                await client.review_queue()
                await client.apply_expiries(["f_1"])
                await client.consolidate("e", "k", "v", ["f_1"])
                await client.undo_consolidation("f_canon")
                await client.local_ingest("t", "c", [])
                await client.import_memory_pack("t", {}, dry_run=True)
                await client.list_extensions()
                self.assertIsNone(await client.get_extension("missing"))
                self.assertFalse(await client.delete_extension("missing"))
                await client.invoke_extension_tool("ext-1", "search")
                return [e async for e in client.subscribe_events(types=["fact.stored"])]

        events = asyncio.run(run())
        self.assertEqual([e["type"] for e in events], ["fact.stored", "session.stored"])

        seen = [(c["method"], c["path"]) for c in CALLS]
        self.assertIn(("GET", "/v1/context"), seen)
        self.assertIn(("POST", "/v1/context"), seen)
        self.assertIn(("POST", "/v1/memory/extract"), seen)
        self.assertIn(("GET", "/v1/memory/candidates"), seen)
        self.assertIn(("POST", "/v1/memory/candidates/c1/promote"), seen)
        self.assertIn(("POST", "/v1/console/review/consolidations/undo"), seen)
        self.assertIn(("POST", "/v1/local/ingest"), seen)
        self.assertIn(("POST", "/v1/memory/import"), seen)
        self.assertIn(("POST", "/v1/extensions/ext-1/tools/search/invoke"), seen)
        self.assertIn(("GET", "/v1/events/stream"), seen)

    def test_sync_and_async_agree_on_every_shared_method_name(self) -> None:
        def surface(cls: type) -> set[str]:
            return {n for n in dir(cls) if not n.startswith("_")}

        sync_only = surface(CueCruxClient) - surface(AsyncCueCruxClient)
        async_only = surface(AsyncCueCruxClient) - surface(CueCruxClient)
        self.assertEqual(sync_only, set(), "sync client has methods the async client lacks")
        self.assertEqual(async_only, set(), "async client has methods the sync client lacks")


if __name__ == "__main__":
    unittest.main()
