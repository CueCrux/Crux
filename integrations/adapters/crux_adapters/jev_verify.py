# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.

"""Verify Jev decision receipts against a pinned daemon key, trusting nothing else.

``/v1/receipts/{id}/verification`` asks the daemon to vouch for its own
receipt, and needs ``receipts:read``. This module checks a receipt the way an
auditor would, with only the daemon's public key, pinned beforehand:

1. **Exactly one signed body** claims the receipt id in
   ``GET /v1/observations/aggregate?kind=model_invocation`` (the daemon does
   not yet refuse a reused id, and anyone with ``sessions:write`` can list
   look-alike records, so zero or several distinct bodies fail).
2. **Ed25519 over the body bytes** verifies with a key from the pinned keyring,
   and that key's id is ``p_`` + the first 32 hex of BLAKE3(public key), the
   same derivation the daemon uses.
3. **The decoded body binds** the receipt id, ``kind: model_invocation`` and
   the body schema.
4. **The decision fact agrees** (when it can be found under ``jev:<entity>``):
   its ``output_hash`` recomputes from its answers and equals the signed one,
   its ``prompt_hash`` and ``retrieval_set_hash`` equal the signed ones, and
   its request id equals the signed ``provider_request_id``.

The keyring file uses ``corecruxctl``'s Ed25519 keyring v1 format
(``{"v": 1, "keys": [{"keyId": ..., "pubKeyBase64": ...}]}``), so the same
file serves ``corecruxctl receipts verify-stream-receipt --keyring``. It is
written only by :func:`pin_key`, an explicit trust-on-first-use step that
refuses to replace a different key unless told to.

Needs the ``jev-verify`` extra (``blake3`` and ``cryptography``).
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from .jev import _OBSERVATION_WINDOW, _cbor_decode, digest

BODY_SCHEMA = "cuecrux.receipt.body.v1"


def default_keyring_path(env: Mapping[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    return Path(env.get("CRUX_RECEIPT_KEYRING") or Path.home() / ".config" / "cuecrux" / "receipt-keyring.json")


def _blake3_hex(data: bytes) -> str:
    try:
        from blake3 import blake3
    except ImportError as err:  # fail closed: never skip the key-id binding
        raise ImportError("receipt verification needs blake3: install cuecrux-adapters[jev-verify]") from err
    return blake3(data).hexdigest()


def key_id_for(public_key: bytes) -> str:
    """The daemon's key id: ``p_`` + the first 32 hex characters of BLAKE3(raw public key)."""
    return "p_" + _blake3_hex(public_key)[:32]


def _ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as err:
        raise ImportError("receipt verification needs cryptography: install cuecrux-adapters[jev-verify]") from err
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except InvalidSignature:
        return False


def load_keyring(path: Path) -> dict[str, bytes]:
    """``keyId -> raw 32-byte key``; raises if the file is missing or malformed."""
    doc = json.loads(path.read_text())
    if doc.get("v") != 1 or not isinstance(doc.get("keys"), list) or not doc["keys"]:
        raise ValueError(f"{path}: not an Ed25519 keyring v1 with at least one key")
    keys: dict[str, bytes] = {}
    for entry in doc["keys"]:
        raw = base64.b64decode(entry["pubKeyBase64"], validate=True)
        if len(raw) != 32:
            raise ValueError(f"{path}: key {entry.get('keyId')!r} is not 32 bytes")
        if key_id_for(raw) != entry["keyId"]:
            raise ValueError(f"{path}: keyId {entry['keyId']!r} does not match its public key")
        keys[entry["keyId"]] = raw
    return keys


def _advertised_key(client: Any) -> bytes:
    """The daemon's receipt-signing public key.

    Prefers the unauthenticated ``GET /v1/receipts/signing-keys`` (newer
    daemons), then ``GET /v1/admin/version`` ``.passport.public_key_hex``
    (needs ``admin:read``).
    """
    try:
        doc = client._request("GET", "/v1/receipts/signing-keys")
        for entry in doc.get("keys") or []:
            if entry.get("public_key_hex"):
                return bytes.fromhex(entry["public_key_hex"])
            if entry.get("pubKeyBase64"):
                return base64.b64decode(entry["pubKeyBase64"], validate=True)
    except Exception:  # older daemon: route absent
        pass
    doc = client._request("GET", "/v1/admin/version")
    hex_key = (doc.get("passport") or {}).get("public_key_hex")
    if not hex_key:
        raise LookupError("daemon advertises no receipt-signing public key")
    return bytes.fromhex(hex_key)


def public_key_from_pem(pem: bytes) -> bytes:
    """Raw 32-byte key from an Ed25519 SubjectPublicKeyInfo PEM (e.g. ``daemon.pub.pem``)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

    key = load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("PEM does not hold an Ed25519 public key")
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def pin_key(client: Any, path: Path, *, replace: bool = False, public_key: bytes | None = None) -> dict[str, Any]:
    """Pin the daemon's key into ``path``.

    With ``public_key`` the key comes out of band (an operator-supplied PEM or
    hex), which is the stronger trust model; otherwise it is fetched from the
    daemon (trust on first use).

    Adding a key the keyring already holds is a no-op. A different key is
    refused unless ``replace`` -- a changed signing key is exactly what a pin
    exists to catch, so replacing one is a deliberate operator act.
    """
    raw = public_key if public_key is not None else _advertised_key(client)
    if len(raw) != 32:
        raise ValueError("daemon public key is not 32 bytes")
    key_id = key_id_for(raw)
    entry = {"keyId": key_id, "pubKeyBase64": base64.b64encode(raw).decode()}
    existing: list[dict[str, str]] = []
    if path.exists():
        current = load_keyring(path)
        if key_id in current:
            return {"key_id": key_id, "keyring": str(path), "changed": False}
        if not replace:
            raise PermissionError(
                f"daemon now signs with {key_id}, which {path} does not pin (pinned: {', '.join(current)}); "
                "re-run with --replace only if the key rotation is expected"
            )
        existing = []  # replace: the old key is dropped, not kept alongside
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"v": 1, "keys": existing + [entry]}, indent=2) + "\n")
    return {"key_id": key_id, "keyring": str(path), "changed": True}


_FIRST_WINDOW = 200


def _listing(client: Any, limit: int, timeout: float) -> list[dict[str, Any]]:
    doc = client._request(
        "GET", "/v1/observations/aggregate", params={"kind": "model_invocation", "limit": limit}, timeout=timeout
    )
    return [o.get("payload") for o in doc.get("observations", []) if isinstance(o.get("payload"), dict)]


def _receipt_records(client: Any, wanted: set[str]) -> list[dict[str, Any]]:
    """Newest ``model_invocation`` records, widening only when a wanted id is missing.

    A busy daemon can take longer than the SDK's default timeout to list the
    route's full 1000-record window, so ask for the newest 200 first. (v0.5.65
    also builds a whole-log `chains` map on every call, ~30 s on host crux;
    hence the long timeouts.)
    """
    payloads = _listing(client, _FIRST_WINDOW, 90.0)
    if wanted - {p.get("receipt_id") for p in payloads}:
        payloads = _listing(client, _OBSERVATION_WINDOW, 180.0)
    return payloads


@dataclass
class ReceiptCheck:
    receipt_id: str
    verified: bool = False
    checks: dict[str, bool] = field(default_factory=dict)
    error: str | None = None
    body: dict[str, Any] | None = None

    def as_json(self) -> dict[str, Any]:
        signed = self.body or {}
        return {
            "receipt_id": self.receipt_id,
            "verified": self.verified,
            "checks": self.checks,
            "error": self.error,
            "model_version": signed.get("model_version"),
            "provider": signed.get("provider"),
            "provider_request_id": signed.get("provider_request_id"),
            "created_at": signed.get("created_at"),
        }


def _check_fact(check: ReceiptCheck, body: dict[str, Any], facts: Iterable[Any]) -> None:
    fact = next((f for f in facts if getattr(f, "source_receipt", None) == check.receipt_id), None)
    if fact is None or fact.value is None:
        check.checks["fact_found"] = False
        return
    check.checks["fact_found"] = True
    record = json.loads(fact.value)
    check.checks["fact_output_hash_recomputes"] = (
        digest({"model": record.get("model_version"), "answers": record.get("answers")}) == body.get("output_hash")
    )
    check.checks["fact_hashes_match_signed"] = all(
        record.get(k) == body.get(k) for k in ("output_hash", "prompt_hash", "retrieval_set_hash")
    )
    ref = record.get("request_id") or record.get("invocation_id")
    signed_ref = body.get("provider_request_id") or body.get("invocation_id")
    check.checks["fact_request_id_matches_signed"] = ref == signed_ref and fact.key == f"decision:{ref}"
    if "retrieved" in record:
        check.checks["fact_retrieval_recomputes"] = digest(record["retrieved"]) == body.get("retrieval_set_hash")


def verify_receipts(
    client: Any,
    receipt_ids: list[str],
    keyring: Mapping[str, bytes],
    *,
    entity: str | None = None,
    facts_for: Callable[[str], list[Any]] | None = None,
) -> list[ReceiptCheck]:
    """Check each receipt as described in the module docstring."""
    payloads = _receipt_records(client, set(receipt_ids))
    facts: list[Any] = []
    if entity:
        facts = (facts_for or client.get_facts_by_entity)(f"jev:{entity}")
    results = []
    for rid in receipt_ids:
        check = ReceiptCheck(receipt_id=rid)
        results.append(check)
        claims = [p for p in payloads if p.get("receipt_id") == rid]
        bodies = {p.get("body_cbor_hex") for p in claims}
        check.checks["single_signed_body"] = len(bodies) == 1
        if len(bodies) != 1:
            check.error = (
                f"not among the newest {_OBSERVATION_WINDOW} model_invocation records"
                if not bodies
                else f"{len(bodies)} distinct bodies claim this id"
            )
            continue
        record = claims[0]
        try:
            body_bytes = bytes.fromhex(record["body_cbor_hex"])
            sig = record.get("sig") or {}
            key_id = sig.get("key_id")
            key = keyring.get(key_id)
            check.checks["key_pinned"] = key is not None
            check.checks["alg_ed25519"] = sig.get("alg") == "ed25519"
            if key is None:
                check.error = f"signed by {key_id}, which the keyring does not pin"
                continue
            check.checks["signature_valid"] = _ed25519_verify(key, bytes.fromhex(sig["signature_hex"]), body_bytes)
            body = _cbor_decode(body_bytes)
            check.body = body
            check.checks["body_binds_receipt_id"] = body.get("receipt_id") == rid
            check.checks["body_kind_model_invocation"] = body.get("kind") == "model_invocation"
            check.checks["body_schema"] = body.get("schema") == BODY_SCHEMA
            if entity:
                _check_fact(check, body, facts)
        except (KeyError, ValueError, TypeError) as err:
            check.error = f"malformed receipt record: {err}"
            continue
        check.verified = all(check.checks.values())
        if not check.verified and check.error is None:
            check.error = "failed: " + ", ".join(k for k, ok in check.checks.items() if not ok)
    return results
