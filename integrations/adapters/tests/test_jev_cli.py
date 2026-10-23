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
                    json.dumps({**REQUEST, "surprise": 1}),
                    # "false" is truthy: it must be refused, not coerced into storing the input.
                    json.dumps({**REQUEST, "store_state": "false"}),
                    json.dumps({**REQUEST, "state_layout": "v9"})]:
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
        self.assertEqual(_run({**REQUEST, "state_layout": "v9"}, ENV, fake_decide)[0], EXIT_USAGE)


class HttpError(Exception):
    def __init__(self, status_code: int) -> None:
        super().__init__(f"HTTP {status_code}")
        self.status_code = status_code


class FakeDaemon:
    """Answers the read-only routes `doctor` probes."""

    def __init__(self, *, stream_receipts: bool = True, context_surface: bool = True, scopes_ok: bool = True,
                 public_key: bytes = b"\x01" * 32) -> None:
        self.stream_receipts, self.context_surface, self.scopes_ok = stream_receipts, context_surface, scopes_ok
        self.public_key = public_key

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        if path == "/v1/version":
            return {"version": "0.5.66", "capabilities": {
                "stream_receipts": {"enabled": self.stream_receipts},
                "context_surface": {"enabled": self.context_surface}}}
        if path == "/v1/receipts/signing-keys":
            return {"v": 1, "keys": [{"publicKeyHex": self.public_key.hex()}]}
        if path == "/v1/context" and not self.context_surface:
            raise HttpError(404)
        if not self.scopes_ok:
            raise HttpError(403)
        return {}


try:
    import blake3  # noqa: F401
    import cryptography  # noqa: F401

    HAVE_VERIFY_DEPS = True
except ImportError:
    HAVE_VERIFY_DEPS = False


@unittest.skipUnless(HAVE_VERIFY_DEPS, "needs the jev-verify extra (blake3, cryptography)")
class Doctor(unittest.TestCase):
    def _doctor(self, daemon: FakeDaemon, env: dict[str, str], pin: bool = True) -> tuple[int, dict[str, Any], str]:
        from crux_adapters.jev_cli import run_doctor
        from crux_adapters.jev_verify import pin_key

        with tempfile.TemporaryDirectory() as tmp:
            keyring = Path(tmp) / "keyring.json"
            if pin:
                pin_key(None, keyring, public_key=daemon.public_key)
            out = io.StringIO()
            code = run_doctor(out, {**env, "CRUX_RECEIPT_KEYRING": str(keyring)}, client_factory=lambda u, t: daemon)
        text = out.getvalue()
        report = json.loads(text)
        return code, {c["name"]: c for c in report["checks"]} | {"ready": report["ready"]}, text

    def test_a_complete_setup_is_ready(self) -> None:
        code, checks, text = self._doctor(FakeDaemon(), ENV)
        self.assertEqual(code, EXIT_OK, text)
        self.assertTrue(checks["ready"])
        self.assertNotIn(SECRET_TOKEN, text)
        self.assertNotIn(SECRET_KEY, text)

    def test_each_missing_daemon_flag_is_named_with_its_fix(self) -> None:
        code, checks, _ = self._doctor(FakeDaemon(stream_receipts=False, context_surface=False), ENV)
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("CORECRUXD_STREAM_RECEIPTS=1", checks["stream_receipts"]["fix"])
        self.assertIn("context_surface: true", checks["context_surface"]["fix"])
        self.assertIn("404", checks["token_reads_context"]["detail"])

    def test_a_token_without_scopes_points_at_the_dev_scopes_trap(self) -> None:
        _, checks, _ = self._doctor(FakeDaemon(scopes_ok=False), ENV)
        self.assertFalse(checks["token_reads_receipts"]["ok"])
        self.assertIn("query:read,facts:write,sessions:write,receipts:read", checks["token_reads_receipts"]["fix"])

    def test_an_unpinned_or_rotated_key_is_reported(self) -> None:
        _, checks, _ = self._doctor(FakeDaemon(), ENV, pin=False)
        self.assertIn("crux-jev pin-key", checks["key_pinned"]["fix"])
        from crux_adapters.jev_cli import run_doctor
        from crux_adapters.jev_verify import pin_key

        with tempfile.TemporaryDirectory() as tmp:
            keyring = Path(tmp) / "keyring.json"
            pin_key(None, keyring, public_key=b"\x02" * 32)
            out = io.StringIO()
            run_doctor(out, {**ENV, "CRUX_RECEIPT_KEYRING": str(keyring)}, client_factory=lambda u, t: FakeDaemon())
        rotated = {c["name"]: c for c in json.loads(out.getvalue())["checks"]}["key_pinned"]
        self.assertFalse(rotated["ok"])
        self.assertIn("--replace", rotated["fix"])

    def test_an_unreachable_daemon_exits_1(self) -> None:
        class Down:
            def _request(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
                raise ConnectionError("refused")

        from crux_adapters.jev_cli import run_doctor

        out = io.StringIO()
        self.assertEqual(run_doctor(out, ENV, client_factory=lambda u, t: Down()), EXIT_FAILED)


@unittest.skipUnless(HAVE_VERIFY_DEPS, "needs the jev-verify extra (blake3, cryptography)")
class PinAndVerifyArgs(unittest.TestCase):
    def test_pin_key_needs_no_token(self) -> None:
        from crux_adapters.jev_cli import run_pin_key

        with tempfile.TemporaryDirectory() as tmp:
            env = {"CRUX_BASE_URL": "http://d", "CRUX_ENV_FILE": "/nonexistent",
                   "CRUX_RECEIPT_KEYRING": str(Path(tmp) / "k.json")}
            seen: list[str] = []

            def factory(url: str, token: str) -> FakeDaemon:
                seen.append(token)
                return FakeDaemon()

            out = io.StringIO()
            self.assertEqual(run_pin_key([], out, env, client_factory=factory), EXIT_OK, out.getvalue())
            self.assertEqual(seen, [""])

    def test_verify_options_need_values(self) -> None:
        from crux_adapters.jev_cli import run_verify

        for args in (["--tenant"], ["r_1", "--actor"], []):
            with self.subTest(args=args):
                self.assertEqual(run_verify(args, io.StringIO(), ENV), EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
