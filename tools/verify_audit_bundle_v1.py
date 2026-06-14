#!/usr/bin/env python3
"""Independent Audit Bundle v1 vector verifier.

This verifier intentionally supports unpacked vector directories. It mirrors the
documented v1 checks without using the Rust implementation.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519


SUPPORTED_VERSION = 1


def canonical_manifest_bytes(manifest: dict) -> bytes:
    signing_manifest = dict(manifest)
    signing_manifest["signature_b64"] = ""
    return json.dumps(signing_manifest, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def fail(manifest: dict | None, reason: str, *, events_match: bool = False, receipts_match: bool = False) -> dict:
    return {
        "ok": False,
        "bundle_format_version": manifest.get("bundle_format_version", 0) if manifest else 0,
        "bundle_id": manifest.get("bundle_id", "") if manifest else "",
        "fact_count": manifest.get("fact_count", 0) if manifest else 0,
        "receipt_count": manifest.get("receipt_count", 0) if manifest else 0,
        "events_jsonl_sha256_match": events_match,
        "receipts_cbor_sha256_match": receipts_match,
        "signature_valid": False,
        "failure_reason": reason,
    }


def verify_vector_dir(path: Path) -> dict:
    manifest_path = path / "manifest.json"
    events_path = path / "events.jsonl"
    receipts_path = path / "receipts.cbor"

    if not manifest_path.exists():
        return fail(None, "missing manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    if manifest.get("bundle_format_version") != SUPPORTED_VERSION:
        return fail(manifest, f"unsupported bundle_format_version: {manifest.get('bundle_format_version')}")
    if not events_path.exists():
        return fail(manifest, "missing events.jsonl")
    if not receipts_path.exists():
        return fail(manifest, "missing receipts.cbor")

    events = events_path.read_bytes()
    receipts = receipts_path.read_bytes()
    events_hash = hashlib.sha256(events).hexdigest()
    receipts_hash = hashlib.sha256(receipts).hexdigest()
    events_match = events_hash == manifest.get("events_jsonl_sha256")
    receipts_match = receipts_hash == manifest.get("receipts_cbor_sha256")

    if not events_match:
        return fail(
            manifest,
            f"events.jsonl sha256 mismatch: expected {manifest.get('events_jsonl_sha256')}, got {events_hash}",
            events_match=False,
            receipts_match=receipts_match,
        )
    if not receipts_match:
        return fail(
            manifest,
            f"receipts.cbor sha256 mismatch: expected {manifest.get('receipts_cbor_sha256')}, got {receipts_hash}",
            events_match=True,
            receipts_match=False,
        )

    try:
        pubkey = base64.b64decode(manifest["signer_public_key_b64"], validate=True)
        signature = base64.b64decode(manifest["signature_b64"], validate=True)
    except Exception as exc:
        return fail(manifest, f"base64 decode failed: {exc}", events_match=True, receipts_match=True)
    if len(pubkey) != 32:
        return fail(manifest, f"invalid public key length: {len(pubkey)}", events_match=True, receipts_match=True)
    if len(signature) != 64:
        return fail(manifest, f"invalid signature length: {len(signature)}", events_match=True, receipts_match=True)

    verifier = ed25519.Ed25519PublicKey.from_public_bytes(pubkey)
    try:
        verifier.verify(signature, canonical_manifest_bytes(manifest))
    except InvalidSignature:
        return fail(
            manifest,
            "manifest signature failed Ed25519 verification",
            events_match=True,
            receipts_match=True,
        )

    return {
        "ok": True,
        "bundle_format_version": manifest["bundle_format_version"],
        "bundle_id": manifest["bundle_id"],
        "fact_count": manifest["fact_count"],
        "receipt_count": manifest["receipt_count"],
        "events_jsonl_sha256_match": True,
        "receipts_cbor_sha256_match": True,
        "signature_valid": True,
        "failure_reason": None,
    }


def compare_expected(report: dict, expected_path: Path) -> tuple[bool, str]:
    if not expected_path.exists():
        return True, ""
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    if report.get("ok") != expected.get("ok"):
        return False, f"expected ok={expected.get('ok')}, got ok={report.get('ok')}"
    needle = expected.get("failure_reason_contains")
    if needle and needle not in (report.get("failure_reason") or ""):
        return False, f"expected failure_reason to contain {needle!r}, got {report.get('failure_reason')!r}"
    return True, ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("vector_dir", type=Path)
    parser.add_argument("--json", action="store_true", help="print report JSON")
    args = parser.parse_args()

    report = verify_vector_dir(args.vector_dir)
    matches, mismatch = compare_expected(report, args.vector_dir / "expected.json")
    if args.json or not matches:
        print(json.dumps(report, indent=2, sort_keys=True))
    if not matches:
        print(mismatch, file=sys.stderr)
        return 1
    return 0 if report["ok"] or (args.vector_dir / "expected.json").exists() else 1


if __name__ == "__main__":
    raise SystemExit(main())
