# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.

"""``crux-jev``: record and verify Jev decisions from any language.

Subcommands (``decide`` is the default when none is given)::

    crux-jev [decide]            JSON request on stdin -> recorded decision on stdout
    crux-jev pin-key [--replace] [--from-pem F | --from-hex H]
                                 pin the daemon's receipt-signing key: out of band from a
                                 PEM/hex, or fetched from the daemon (trust on first use)
    crux-jev verify [--entity E] RECEIPT_ID...
                                 check receipts against the pinned key only; with
                                 --entity also check each jev:E decision fact agrees

Callers that are not Python (a Node build tool, a shell script, an agent's
sandbox) get the same signed receipt and ``jev:<entity>`` fact as
:func:`crux_adapters.jev.decide`, without re-implementing its canonical
hashing. One JSON request on stdin, one JSON result on stdout::

    echo '{"entity": "paracrux:ci-triage",
           "questions": {"cls": {"type": "choice", "instructions": "...", "criteria": {...}}},
           "untrusted": "CI job: ...", "token_budget": 400}' | crux-jev

Request fields: ``entity`` and ``questions`` (required); ``untrusted``,
``token_budget`` (default 400), ``crux_query``, ``model`` (default
``jev-latest``), ``store_state`` (default false), ``provider``,
``state_layout`` (``v0`` default, or the measured ``split-v1``) and
``untrusted_source`` (label for the untrusted input under ``split-v1``).

Result: ``recorded``, ``answers``, ``model_version``, ``request_id``,
``invocation_id``, ``receipt_id``, ``fact_id``, the three hashes,
``context_items`` and ``context_truncated``. Nothing secret is ever printed.

Exit codes (decide): 0 recorded; 3 Jev answered but the decision was NOT recorded (the
result still carries the answers, with ``recorded: false`` and ``error``; a
guardrail caller must fail closed); 2 bad request or missing configuration;
1 Crux retrieval or Jev failed before any answer.

Configuration, first match wins; secrets are only ever read from files or the
environment, never from argv:

* daemon URL: ``CRUX_BASE_URL``, ``CRUX_HTTP_URL``, then ``CRUX_HTTP_URL`` in
  the env file;
* daemon token: the file named by ``CRUX_TOKEN_FILE``, ``CRUX_AGENT_TOKEN``,
  then ``CRUX_AGENT_TOKEN`` in the env file;
* Jev key: ``TYPESAFE_API_KEY``, the file named by ``JEV_CREDENTIAL_FILE``,
  then ``~/.config/typesafe/api_key``.

The env file is ``CRUX_ENV_FILE`` or ``~/.config/cuecrux/env`` (``KEY=value``
or ``export KEY=value`` lines). File fallbacks matter under sandboxes such as
Codex, which strip environment variables named like ``*KEY*`` or ``*TOKEN*``.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, TextIO

from .jev import DecisionNotRecorded, JevDecision, decide, jev_http

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_NOT_RECORDED = 3

DEFAULT_TOKEN_BUDGET = 400


class ConfigError(Exception):
    """Missing or unusable configuration; never carries a secret value."""


def _read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        text = path.read_text()
    except OSError:
        return values
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        name, sep, value = line.partition("=")
        if not sep:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[name.strip()] = value
    return values


def _read_secret_file(path: str, what: str) -> str:
    try:
        value = Path(path).expanduser().read_text().strip()
    except OSError as err:
        raise ConfigError(f"{what} file {path!r} is unreadable ({err.strerror})") from None
    if not value:
        raise ConfigError(f"{what} file {path!r} is empty")
    return value


def resolve_config(env: Mapping[str, str] | None = None, home: Path | None = None) -> dict[str, str]:
    """Daemon URL, daemon token and Jev key, by the order in the module docstring."""
    env = os.environ if env is None else env
    home = Path.home() if home is None else home
    env_file = Path(env.get("CRUX_ENV_FILE") or home / ".config" / "cuecrux" / "env")
    file_values = _read_env_file(env_file)

    url = env.get("CRUX_BASE_URL") or env.get("CRUX_HTTP_URL") or file_values.get("CRUX_HTTP_URL")
    if not url:
        raise ConfigError(f"no daemon URL: set CRUX_BASE_URL or CRUX_HTTP_URL in {env_file}")

    if env.get("CRUX_TOKEN_FILE"):
        token = _read_secret_file(env["CRUX_TOKEN_FILE"], "CRUX_TOKEN_FILE")
    else:
        token = (env.get("CRUX_AGENT_TOKEN") or file_values.get("CRUX_AGENT_TOKEN") or "").strip()
    if not token:
        raise ConfigError(f"no daemon token: set CRUX_TOKEN_FILE, or CRUX_AGENT_TOKEN in {env_file}")

    if (env.get("TYPESAFE_API_KEY") or "").strip():
        key = env["TYPESAFE_API_KEY"].strip()
    elif env.get("JEV_CREDENTIAL_FILE"):
        key = _read_secret_file(env["JEV_CREDENTIAL_FILE"], "JEV_CREDENTIAL_FILE")
    else:
        key_file = home / ".config" / "typesafe" / "api_key"
        if not key_file.exists():
            raise ConfigError(f"no Jev key: set TYPESAFE_API_KEY or JEV_CREDENTIAL_FILE, or create {key_file}")
        key = _read_secret_file(str(key_file), "Jev key")
    return {"url": url, "token": token, "jev_key": key}


def parse_request(text: str) -> dict[str, Any]:
    try:
        request = json.loads(text)
    except json.JSONDecodeError as err:
        raise ValueError(f"request is not JSON: {err}") from None
    if not isinstance(request, dict):
        raise ValueError("request must be a JSON object")
    entity = request.get("entity")
    if not isinstance(entity, str) or not entity.strip():
        raise ValueError("request.entity must be a non-empty string")
    questions = request.get("questions")
    if not isinstance(questions, dict) or not questions:
        raise ValueError("request.questions must be a non-empty object")
    budget = request.get("token_budget", DEFAULT_TOKEN_BUDGET)
    if not isinstance(budget, int) or isinstance(budget, bool) or budget < 0:
        raise ValueError("request.token_budget must be a non-negative integer")
    known = {"entity", "questions", "untrusted", "token_budget", "crux_query", "model", "store_state", "provider",
             "state_layout", "untrusted_source"}
    unknown = sorted(set(request) - known)
    if unknown:
        raise ValueError(f"unknown request fields: {', '.join(unknown)}")
    return request


def _result(decision: JevDecision, recorded: bool, error: str | None = None) -> dict[str, Any]:
    bundle = decision.bundle
    out: dict[str, Any] = {
        "recorded": recorded,
        "answers": decision.answers,
        "model_version": decision.model_version,
        "request_id": decision.request_id,
        "invocation_id": decision.invocation_id,
        "receipt_id": decision.receipt_id,
        "fact_id": decision.fact_id,
        "prompt_hash": decision.prompt_hash,
        "retrieval_set_hash": decision.retrieval_set_hash,
        "output_hash": decision.output_hash or None,
        "context_items": len(bundle.items) if bundle is not None else 0,
        "context_truncated": bool(bundle.truncated) if bundle is not None else False,
    }
    if error is not None:
        out["error"] = error
    return out


def run(
    stdin: TextIO,
    stdout: TextIO,
    env: Mapping[str, str] | None = None,
    *,
    decide_fn: Callable[..., JevDecision] = decide,
    client_factory: Callable[[str, str], Any] | None = None,
    jev_factory: Callable[[str], Any] = lambda key: jev_http(api_key=key),
) -> int:
    def emit(payload: dict[str, Any]) -> None:
        stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")

    try:
        request = parse_request(stdin.read())
        config = resolve_config(env)
    except (ValueError, ConfigError) as err:
        emit({"recorded": False, "error": str(err)})
        return EXIT_USAGE

    if client_factory is None:
        from cuecrux_client import CueCruxClient

        def client_factory(url: str, token: str) -> Any:
            return CueCruxClient(url, token=token)

    client = client_factory(config["url"], config["token"])
    kwargs: dict[str, Any] = {
        "entity": request["entity"],
        "token_budget": request.get("token_budget", DEFAULT_TOKEN_BUDGET),
        "crux_query": request.get("crux_query"),
        "untrusted": request.get("untrusted"),
        "jev": jev_factory(config["jev_key"]),
        "model": request.get("model", "jev-latest"),
        "store_state": bool(request.get("store_state", False)),
    }
    if request.get("provider"):
        kwargs["provider"] = request["provider"]
    if request.get("state_layout"):
        kwargs["state_layout"] = request["state_layout"]
    if request.get("untrusted_source"):
        kwargs["untrusted_source"] = request["untrusted_source"]
    try:
        decision = decide_fn(client, request["questions"], **kwargs)
    except DecisionNotRecorded as err:
        emit(_result(err.decision, recorded=False, error=str(err)))
        return EXIT_NOT_RECORDED
    except Exception as err:  # retrieval or Jev failed: nothing was answered
        emit({"recorded": False, "error": f"{type(err).__name__}: {err}"})
        return EXIT_FAILED
    emit(_result(decision, recorded=True))
    return EXIT_OK


EXIT_UNVERIFIED = 4


def _client_from_env(env: Mapping[str, str] | None, client_factory: Callable[[str, str], Any] | None) -> Any:
    env = os.environ if env is None else env
    home = Path.home()
    env_file = Path(env.get("CRUX_ENV_FILE") or home / ".config" / "cuecrux" / "env")
    file_values = _read_env_file(env_file)
    url = env.get("CRUX_BASE_URL") or env.get("CRUX_HTTP_URL") or file_values.get("CRUX_HTTP_URL")
    if env.get("CRUX_TOKEN_FILE"):
        token = _read_secret_file(env["CRUX_TOKEN_FILE"], "CRUX_TOKEN_FILE")
    else:
        token = (env.get("CRUX_AGENT_TOKEN") or file_values.get("CRUX_AGENT_TOKEN") or "").strip()
    if not url or not token:
        raise ConfigError(f"no daemon URL or token: see crux-jev --help (env file {env_file})")
    if client_factory is None:
        from cuecrux_client import CueCruxClient

        return CueCruxClient(url, token=token)
    return client_factory(url, token)


def run_pin_key(args: list[str], stdout: TextIO, env: Mapping[str, str] | None = None, *, client_factory: Any = None) -> int:
    from .jev_verify import default_keyring_path, pin_key, public_key_from_pem

    try:
        public_key = None
        if "--from-pem" in args:
            public_key = public_key_from_pem(Path(args[args.index("--from-pem") + 1]).read_bytes())
        elif "--from-hex" in args:
            public_key = bytes.fromhex(args[args.index("--from-hex") + 1])
        client = None if public_key is not None else _client_from_env(env, client_factory)
        result = pin_key(client, default_keyring_path(env), replace="--replace" in args, public_key=public_key)
    except PermissionError as err:  # a changed key: the pin did its job
        stdout.write(json.dumps({"pinned": False, "error": str(err)}) + "\n")
        return EXIT_UNVERIFIED
    except (ConfigError, ImportError, LookupError, ValueError, OSError, IndexError) as err:
        stdout.write(json.dumps({"pinned": False, "error": str(err)}) + "\n")
        return EXIT_USAGE
    except Exception as err:  # e.g. a 403: the token may not read /v1/admin/version
        stdout.write(json.dumps({"pinned": False, "error": f"{type(err).__name__}: {err}; pin out of band with --from-pem or --from-hex"}) + "\n")
        return EXIT_FAILED
    stdout.write(json.dumps({"pinned": True, **result}) + "\n")
    return EXIT_OK


def run_verify(args: list[str], stdout: TextIO, env: Mapping[str, str] | None = None, *, client_factory: Any = None) -> int:
    from .jev_verify import default_keyring_path, load_keyring, verify_receipts

    entity = None
    ids: list[str] = []
    it = iter(args)
    for arg in it:
        if arg == "--entity":
            entity = next(it, None)
        else:
            ids.append(arg)
    if not ids or (entity is not None and not entity):
        stdout.write(json.dumps({"verified": False, "error": "usage: crux-jev verify [--entity E] RECEIPT_ID..."}) + "\n")
        return EXIT_USAGE
    path = default_keyring_path(env)
    try:
        keyring = load_keyring(path)
        client = _client_from_env(env, client_factory)
        checks = verify_receipts(client, ids, keyring, entity=entity)
    except FileNotFoundError:
        stdout.write(json.dumps({"verified": False, "error": f"no keyring at {path}: run `crux-jev pin-key` first"}) + "\n")
        return EXIT_USAGE
    except (ConfigError, ImportError, ValueError) as err:
        stdout.write(json.dumps({"verified": False, "error": str(err)}) + "\n")
        return EXIT_USAGE
    except Exception as err:  # daemon unreachable, timeout, 403: nothing was verified
        stdout.write(json.dumps({"verified": False, "error": f"{type(err).__name__}: {err}"}) + "\n")
        return EXIT_FAILED
    results = [c.as_json() for c in checks]
    ok = all(c.verified for c in checks)
    stdout.write(json.dumps({"verified": ok, "keyring": str(path), "receipts": results}, ensure_ascii=False) + "\n")
    return EXIT_OK if ok else EXIT_UNVERIFIED


def main() -> None:
    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(EXIT_OK)
    if args and args[0] == "verify":
        sys.exit(run_verify(args[1:], sys.stdout))
    if args and args[0] == "pin-key":
        sys.exit(run_pin_key(args[1:], sys.stdout))
    if args and args[0] == "decide":
        args = args[1:]
    if args:
        print(f"crux-jev: unknown arguments {args!r}; see --help", file=sys.stderr)
        sys.exit(EXIT_USAGE)
    sys.exit(run(sys.stdin, sys.stdout))


if __name__ == "__main__":
    main()
