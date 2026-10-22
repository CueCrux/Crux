# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.

"""Offline receipt verification against a pinned key: each check must pass on
a genuine receipt and fail on the attack it exists to catch. Receipts are
built here with a throwaway Ed25519 key, so nothing touches a daemon.
"""

from __future__ import annotations

import base64
import json
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    import blake3  # noqa: F401

    HAVE_DEPS = True
except ImportError:  # the jev-verify extra is optional
    HAVE_DEPS = False

from crux_adapters.jev import digest


def _cbor_text(value: str) -> bytes:
    raw = value.encode()
    n = len(raw)
    head = bytes([0x60 | n]) if n < 24 else bytes([0x78, n]) if n < 256 else b"\x79" + struct.pack(">H", n)
    return head + raw


def _cbor_map(items: dict[str, str]) -> bytes:
    """Encode a map of text to text, the subset the receipt body uses here."""
    out = bytes([0xA0 | len(items)])
    for k, v in items.items():
        out += _cbor_text(k) + _cbor_text(v)
    return out


if HAVE_DEPS:
    from crux_adapters.jev_verify import key_id_for, load_keyring, pin_key, verify_receipts

    ANSWERS = {"cls": {"type": "choice", "choice": "runner_infra", "confidence": 1.0}}
    OUTPUT_HASH = digest({"model": "jev-1.13.0", "answers": ANSWERS})

    class Signer:
        def __init__(self) -> None:
            self.key = Ed25519PrivateKey.generate()
            self.public = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            self.key_id = key_id_for(self.public)

        def record(self, receipt_id: str, **body_overrides: str) -> dict[str, Any]:
            body = {
                "schema": "cuecrux.receipt.body.v1",
                "kind": "model_invocation",
                "receipt_id": receipt_id,
                "model_version": "jev-1.13.0",
                "provider": "typesafe",
                "provider_request_id": "req_1",
                "prompt_hash": "sha256:p",
                "retrieval_set_hash": "sha256:r",
                "output_hash": OUTPUT_HASH,
                **body_overrides,
            }
            cbor = _cbor_map(body)
            return {
                "receipt_id": receipt_id,
                "body_cbor_hex": cbor.hex(),
                "sig": {"alg": "ed25519", "key_id": self.key_id, "signature_hex": self.key.sign(cbor).hex()},
            }

    def _client(records: list[dict[str, Any]]) -> Any:
        def request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
            assert path == "/v1/observations/aggregate"
            return {"observations": [{"payload": r} for r in records]}

        return SimpleNamespace(_request=request)

    def _fact(receipt_id: str, **overrides: Any) -> Any:
        record = {"answers": ANSWERS, "model_version": "jev-1.13.0", "request_id": "req_1",
                  "prompt_hash": "sha256:p", "retrieval_set_hash": "sha256:r", "output_hash": OUTPUT_HASH, **overrides}
        return SimpleNamespace(key=f"decision:{record['request_id']}", value=json.dumps(record), source_receipt=receipt_id)


@unittest.skipUnless(HAVE_DEPS, "needs the jev-verify extra (blake3, cryptography)")
class Verification(unittest.TestCase):
    def setUp(self) -> None:
        self.signer = Signer()
        self.keyring = {self.signer.key_id: self.signer.public}

    def _one(self, records: list[dict[str, Any]], facts: list[Any] | None = None, entity: str | None = None) -> Any:
        (check,) = verify_receipts(_client(records), ["r_1"], self.keyring, entity=entity, facts_for=lambda _: facts or [])
        return check

    def test_genuine_receipt_and_fact_verify(self) -> None:
        check = self._one([self.signer.record("r_1")], [_fact("r_1")], entity="e")
        self.assertTrue(check.verified, check.checks)
        self.assertTrue(check.checks["fact_output_hash_recomputes"])

    def test_missing_receipt_fails(self) -> None:
        check = self._one([])
        self.assertFalse(check.verified)
        self.assertIn("not among", check.error)

    def test_look_alike_claiming_the_same_id_fails_closed(self) -> None:
        forged = Signer().record("r_1", output_hash="sha256:forged")
        check = self._one([self.signer.record("r_1"), forged])
        self.assertFalse(check.verified)
        self.assertFalse(check.checks["single_signed_body"])

    def test_body_signed_by_an_unpinned_key_fails(self) -> None:
        check = self._one([Signer().record("r_1")])
        self.assertFalse(check.verified)
        self.assertFalse(check.checks["key_pinned"])

    def test_body_edited_after_signing_fails(self) -> None:
        record = self.signer.record("r_1")
        body = bytearray.fromhex(record["body_cbor_hex"])
        body[-1] ^= 0x01
        record["body_cbor_hex"] = body.hex()
        check = self._one([record])
        self.assertFalse(check.checks["signature_valid"])
        self.assertFalse(check.verified)

    def test_signed_body_for_another_id_fails(self) -> None:
        record = self.signer.record("r_other")
        record["receipt_id"] = "r_1"  # the listing claims r_1, the signed body says otherwise
        check = self._one([record])
        self.assertFalse(check.checks["body_binds_receipt_id"])

    def test_fact_with_edited_answers_fails(self) -> None:
        edited = {"cls": {"type": "choice", "choice": "behaviour_regression", "confidence": 1.0}}
        check = self._one([self.signer.record("r_1")], [_fact("r_1", answers=edited)], entity="e")
        self.assertFalse(check.checks["fact_output_hash_recomputes"])
        self.assertFalse(check.verified)

    def test_fact_pointing_at_another_request_fails(self) -> None:
        check = self._one([self.signer.record("r_1")], [_fact("r_1", request_id="req_2")], entity="e")
        self.assertFalse(check.checks["fact_request_id_matches_signed"])

    def test_missing_fact_fails_when_an_entity_is_given(self) -> None:
        check = self._one([self.signer.record("r_1")], [], entity="e")
        self.assertFalse(check.checks["fact_found"])
        self.assertFalse(check.verified)


@unittest.skipUnless(HAVE_DEPS, "needs the jev-verify extra (blake3, cryptography)")
class Pinning(unittest.TestCase):
    def _daemon(self, public: bytes) -> Any:
        def request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
            if path == "/v1/receipts/signing-keys":
                raise RuntimeError("404")  # an older daemon
            return {"passport": {"public_key_hex": public.hex()}}

        return SimpleNamespace(_request=request)

    def test_first_pin_writes_a_corecruxctl_compatible_keyring(self) -> None:
        signer = Signer()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "k.json"
            result = pin_key(self._daemon(signer.public), path)
            self.assertTrue(result["changed"])
            doc = json.loads(path.read_text())
            self.assertEqual(doc, {"v": 1, "keys": [{"keyId": signer.key_id, "pubKeyBase64": base64.b64encode(signer.public).decode()}]})
            self.assertEqual(load_keyring(path), {signer.key_id: signer.public})
            self.assertFalse(pin_key(self._daemon(signer.public), path)["changed"])

    def test_a_changed_daemon_key_is_refused_unless_replacing(self) -> None:
        old, new = Signer(), Signer()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "k.json"
            pin_key(self._daemon(old.public), path)
            with self.assertRaises(PermissionError):
                pin_key(self._daemon(new.public), path)
            self.assertEqual(list(load_keyring(path)), [old.key_id])
            pin_key(self._daemon(new.public), path, replace=True)
            self.assertEqual(list(load_keyring(path)), [new.key_id])

    def test_a_keyring_whose_key_id_does_not_match_its_key_is_rejected(self) -> None:
        signer = Signer()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "k.json"
            path.write_text(json.dumps({"v": 1, "keys": [{"keyId": "p_" + "0" * 32, "pubKeyBase64": base64.b64encode(signer.public).decode()}]}))
            with self.assertRaises(ValueError):
                load_keyring(path)


if __name__ == "__main__":
    unittest.main()
