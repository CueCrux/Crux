#!/usr/bin/env python3
"""Generate Audit Bundle v1 unpacked conformance vectors.

The vectors are intentionally small and deterministic. They are unpacked bundle
directories so git can review the JSON members directly; `receipts.cbor` is
generated as the raw CBOR empty-array byte. To regenerate the committed
archive-level `audit-bundle.tar.zst` fixtures, run:

    cargo run -p corecrux-receipts --example gen_audit_bundle_archive_vectors
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "crates/corecrux-receipts/vectors/audit-bundle-v1"


def canonical_manifest_bytes(manifest: dict) -> bytes:
    signing_manifest = dict(manifest)
    signing_manifest["signature_b64"] = ""
    return json.dumps(signing_manifest, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def write_json(path: Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def build_manifest(events: bytes, receipts: bytes) -> dict:
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([0x42]) * 32)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    manifest = {
        "bundle_format_version": 1,
        "bundle_id": "vector-valid-minimal",
        "since": "2026-06-14T00:00:00Z",
        "until": "2026-06-14T00:01:00Z",
        "generated_at": "2026-06-14T00:01:00Z",
        "scope": {
            "include_reserved": False,
        },
        "fact_count": 1,
        "receipt_count": 0,
        "events_jsonl_sha256": hashlib.sha256(events).hexdigest(),
        "receipts_cbor_sha256": hashlib.sha256(receipts).hexdigest(),
        "signer_public_key_b64": base64.b64encode(public_key).decode("ascii"),
        "signer_key_id": "vector-ed25519-42",
        "signature_b64": "",
    }
    signature = private_key.sign(canonical_manifest_bytes(manifest))
    manifest["signature_b64"] = base64.b64encode(signature).decode("ascii")
    return manifest


def main() -> None:
    events = (
        b'{"fact_id":"f_vector_001","entity":"vector:fixture","key":"status",'
        b'"value":"shipped","confidence":1.0,"stored_at":"2026-06-14T00:00:30Z",'
        b'"tokens":1,"deleted":false,"version":1}\n'
    )
    receipts = b"\x80"
    manifest = build_manifest(events, receipts)

    valid = VECTORS / "valid-minimal"
    valid.mkdir(parents=True, exist_ok=True)
    write_json(valid / "manifest.json", manifest)
    (valid / "events.jsonl").write_bytes(events)
    (valid / "receipts.cbor").write_bytes(receipts)
    write_json(valid / "expected.json", {"ok": True})

    invalid = VECTORS / "invalid-events-hash"
    invalid.mkdir(parents=True, exist_ok=True)
    write_json(invalid / "manifest.json", manifest)
    (invalid / "events.jsonl").write_bytes(events.replace(b"shipped", b"tampered"))
    (invalid / "receipts.cbor").write_bytes(receipts)
    write_json(
        invalid / "expected.json",
        {"ok": False, "failure_reason_contains": "events.jsonl sha256 mismatch"},
    )


if __name__ == "__main__":
    main()
