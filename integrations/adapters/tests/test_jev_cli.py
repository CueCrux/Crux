# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.

"""``crux-jev``: request parsing, configuration order, exit codes and the
promise that no secret reaches stdout. ``decide`` itself is covered by
``test_jev.py``; here it is replaced by a stub so nothing touches a network.
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from crux_adapters.jev import DecisionNotRecorded, JevDecision
from crux_adapters.jev_cli import (
    EXIT_FAILED,
    EXIT_NOT_RECORDED,
    EXIT_OK,
    EXIT_USAGE,
    ConfigError,
    parse_request,
    resolve_config,
    run,
)

SECRET_TOKEN = "tok-SECRET-daemon"
SECRET_KEY = "key-SECRET-jev"


def _decision(**overrides: Any) -> JevDecision:
    fields: dict[str, Any] = dict(
        answers={"cls": {"type": "choice", "choice": "runner_infra", "confidence": 1.0}},
        model_version="jev-1.13.0",
        request_id="req_1",
        invocation_id="inv_1",
        prompt_hash="sha256:p",
        retrieval_set_hash="sha256:r",
        output_hash="sha256:o",
        state={"trusted_context": [], "untrusted_input": "x"},
        bundle=None,
        raw={},
        receipt_id="r_1",
        fact_id="f_1",
    )
    fields.update(overrides)
    return JevDecision(**fields)


REQUEST = {"entity": "paracrux:ci-triage", "questions": {"cls": {"type": "noul", "instructions": "?"}}, "untrusted": "log"}
ENV = {"CRUX_BASE_URL": "http://daemon.test", "CRUX_AGENT_TOKEN": SECRET_TOKEN, "TYPESAFE_API_KEY": SECRET_KEY, "CRUX_ENV_FILE": "/nonexistent"}


def _run(request: Any, env: dict[str, str], decide_fn: Any) -> tuple[int, dict[str, Any], str]:
    out = io.StringIO()
    stdin = io.StringIO(request if isinstance(request, str) else json.dumps(request))
    code = run(stdin, out, env, decide_fn=decide_fn, client_factory=lambda url, token: ("client", url, token),
               jev_factory=lambda key: ("jev", key))
    text = out.getvalue()
    return code, json.loads(text), text


class Requests(unittest.TestCase):
    def test_minimal_request_is_accepted(self) -> None:
        self.assertEqual(parse_request(json.dumps(REQUEST))["entity"], "paracrux:ci-triage")

    def test_bad_requests_are_refused(self) -> None:
        for bad in ["not json", "[]", json.dumps({"questions": {"a": {}}}), json.dumps({"entity": "e", "questions": {}}),
                    json.dumps({**REQUEST, "token_budget": -1}), json.dumps({**REQUEST, "token_budget": True}),
                    json.dumps({**REQUEST, "surprise": 1})]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_request(bad)


class Configuration(unittest.TestCase):
    def test_environment_wins(self) -> None:
        self.assertEqual(resolve_config(ENV), {"url": "http://daemon.test", "token": SECRET_TOKEN, "jev_key": SECRET_KEY})

    def test_file_fallbacks_survive_a_sandbox_that_strips_key_and_token_variables(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / ".config" / "cuecrux").mkdir(parents=True)
            (home / ".config" / "cuecrux" / "env").write_text(
                f"# comment\nexport CRUX_HTTP_URL=http://file.test\nCRUX_AGENT_TOKEN='{SECRET_TOKEN}'\n")
            (home / ".config" / "typesafe").mkdir(parents=True)
            (home / ".config" / "typesafe" / "api_key").write_text(SECRET_KEY + "\n")
            self.assertEqual(resolve_config({}, home=home), {"url": "http://file.test", "token": SECRET_TOKEN, "jev_key": SECRET_KEY})

    def test_token_and_key_files_take_precedence_over_the_env_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            token_file, key_file = Path(tmp) / "t", Path(tmp) / "k"
            token_file.write_text("from-file\n")
            key_file.write_text("key-from-file\n")
            env = {"CRUX_BASE_URL": "http://d", "CRUX_TOKEN_FILE": str(token_file), "JEV_CREDENTIAL_FILE": str(key_file), "CRUX_ENV_FILE": "/nonexistent"}
            self.assertEqual(resolve_config(env, home=Path(tmp)), {"url": "http://d", "token": "from-file", "jev_key": "key-from-file"})

    def test_missing_configuration_is_named_without_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ConfigError, "no daemon URL"):
                resolve_config({"CRUX_ENV_FILE": "/nonexistent"}, home=Path(tmp))
            with self.assertRaisesRegex(ConfigError, "no daemon token"):
                resolve_config({"CRUX_BASE_URL": "http://d", "CRUX_ENV_FILE": "/nonexistent"}, home=Path(tmp))
            with self.assertRaisesRegex(ConfigError, "no Jev key"):
                resolve_config({"CRUX_BASE_URL": "http://d", "CRUX_AGENT_TOKEN": "t", "CRUX_ENV_FILE": "/nonexistent"}, home=Path(tmp))


class Runs(unittest.TestCase):
    def test_recorded_decision_exits_0_and_passes_the_request_through(self) -> None:
        seen: dict[str, Any] = {}

        def fake_decide(client: Any, questions: Any, **kwargs: Any) -> JevDecision:
            seen.update(client=client, questions=questions, **kwargs)
            return _decision()

        code, out, text = _run({**REQUEST, "token_budget": 250, "store_state": True}, ENV, fake_decide)
        self.assertEqual(code, EXIT_OK)
        self.assertTrue(out["recorded"])
        self.assertEqual((out["receipt_id"], out["fact_id"], out["model_version"]), ("r_1", "f_1", "jev-1.13.0"))
        self.assertEqual(seen["client"], ("client", "http://daemon.test", SECRET_TOKEN))
        self.assertEqual(seen["jev"], ("jev", SECRET_KEY))
        self.assertEqual((seen["entity"], seen["token_budget"], seen["untrusted"], seen["store_state"]), ("paracrux:ci-triage", 250, "log", True))
        self.assertNotIn(SECRET_TOKEN, text)
        self.assertNotIn(SECRET_KEY, text)

    def test_unrecorded_decision_exits_3_and_keeps_the_answers(self) -> None:
        def fake_decide(client: Any, questions: Any, **kwargs: Any) -> JevDecision:
            raise DecisionNotRecorded("receipt not minted", _decision(receipt_id=None, fact_id=None))

        code, out, _ = _run(REQUEST, ENV, fake_decide)
        self.assertEqual(code, EXIT_NOT_RECORDED)
        self.assertFalse(out["recorded"])
        self.assertEqual(out["answers"]["cls"]["choice"], "runner_infra")
        self.assertIn("receipt not minted", out["error"])

    def test_failure_before_an_answer_exits_1(self) -> None:
        def fake_decide(client: Any, questions: Any, **kwargs: Any) -> JevDecision:
            raise RuntimeError("context surface 404")

        code, out, _ = _run(REQUEST, ENV, fake_decide)
        self.assertEqual(code, EXIT_FAILED)
        self.assertNotIn("answers", out)

    def test_usage_errors_exit_2_before_any_call(self) -> None:
        def fake_decide(*args: Any, **kwargs: Any) -> JevDecision:
            raise AssertionError("must not be called")

        self.assertEqual(_run("nope", ENV, fake_decide)[0], EXIT_USAGE)
        self.assertEqual(_run(REQUEST, {"CRUX_ENV_FILE": "/nonexistent"}, fake_decide)[0], EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
