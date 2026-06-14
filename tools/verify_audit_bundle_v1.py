#!/usr/bin/env python3
"""Independent Audit Bundle v1 vector verifier.

This verifier intentionally supports unpacked vector directories. It mirrors the
documented v1 checks without using the Rust implementation.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
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


REQUIRED_MEMBERS = ("manifest.json", "events.jsonl", "receipts.cbor")


def read_archive_members(path: Path) -> tuple[dict, bytes, bytes]:
    try:
        import zstandard as zstd  # type: ignore[import-not-found]
    except Exception:
        zstd = None

    if zstd is not None:
        with path.open("rb") as fh:
            with zstd.ZstdDecompressor().stream_reader(fh) as reader:
                tar_bytes = reader.read()
    elif shutil.which("zstd"):
        tar_bytes = subprocess.check_output(["zstd", "-dc", str(path)])
    else:
        raise RuntimeError("verifying .tar.zst vectors requires python zstandard or zstd CLI")

    members: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
        for member in archive.getmembers():
            if member.name not in REQUIRED_MEMBERS:
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            members[member.name] = extracted.read()

    missing = [name for name in REQUIRED_MEMBERS if name not in members]
    if missing:
        raise RuntimeError(f"archive missing required member(s): {', '.join(missing)}")
    manifest = json.loads(members["manifest.json"].decode("utf-8"))
    return manifest, members["events.jsonl"], members["receipts.cbor"]


def read_unpacked_members(path: Path) -> tuple[dict, bytes, bytes] | dict:
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

    return manifest, events_path.read_bytes(), receipts_path.read_bytes()


def verify_vector(path: Path) -> dict:
    try:
        if path.is_dir():
            loaded = read_unpacked_members(path)
            expected_path = path / "expected.json"
        elif path.name.endswith(".tar.zst"):
            loaded = read_archive_members(path)
            expected_path = path.parent / "expected.json"
        else:
            return fail(None, "expected unpacked vector directory or .tar.zst archive")
    except Exception as exc:
        return fail(None, str(exc))

    if isinstance(loaded, dict):
        return loaded
    manifest, events, receipts = loaded

    if manifest.get("bundle_format_version") != SUPPORTED_VERSION:
        return fail(manifest, f"unsupported bundle_format_version: {manifest.get('bundle_format_version')}")

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
    parser.add_argument("vector", type=Path, help="unpacked vector directory or audit-bundle.tar.zst")
    parser.add_argument("--json", action="store_true", help="print report JSON")
    args = parser.parse_args()

    report = verify_vector(args.vector)
    expected_path = args.vector / "expected.json" if args.vector.is_dir() else args.vector.parent / "expected.json"
    matches, mismatch = compare_expected(report, expected_path)
    if args.json or not matches:
        print(json.dumps(report, indent=2, sort_keys=True))
    if not matches:
        print(mismatch, file=sys.stderr)
        return 1
    return 0 if report["ok"] or expected_path.exists() else 1


if __name__ == "__main__":
    raise SystemExit(main())
