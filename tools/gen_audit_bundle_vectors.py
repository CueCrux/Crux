#!/usr/bin/env python3
"""Generate Audit Bundle v1 conformance vectors.

Each vector is emitted in two interchangeable forms so downstream tooling can
review and verify whichever it prefers:

* an **unpacked directory** holding the three bundle members
  (`manifest.json`, `events.jsonl`, `receipts.cbor`) plus `expected.json`, so
  git can diff the JSON/CBOR members directly; and
* a deterministic `audit-bundle.tar.zst` matching the production on-disk layout
  (`tar.zst` with the same three members), so external verifiers can exercise
  the real archive shape.

The Rust example `cargo run -p corecrux-receipts --example
gen_audit_bundle_archive_vectors` produces a byte-canonical archive from the
same unpacked members; this generator is the toolchain-free fallback (stdlib
`tarfile` + a zstd backend) so the vectors can be regenerated and verified
without a Rust build. The two archives are semantically identical — same three
members, same content — and both are accepted/rejected identically by
`tools/verify_audit_bundle_v1.py`.

zstd backend: the `zstandard` Python module is preferred; the `zstd` CLI is used
as a fallback. CI installs `zstandard` (see `.github/workflows/audit-vectors.yml`).
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import shutil
import subprocess
import tarfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "crates/corecrux-receipts/vectors/audit-bundle-v1"

ARCHIVE_FILENAME = "audit-bundle.tar.zst"
# Order matters: the verifier reads members by name, but keeping a stable order
# (and deterministic tar headers) makes the archive reproducible.
BUNDLE_MEMBERS = ("manifest.json", "events.jsonl", "receipts.cbor")


# Domain-separation tag prefixed to the v2 signing input; mirrors
# corecrux_receipts::audit_bundle_v1::AUDIT_BUNDLE_SIGNING_DOMAIN and the verifier.
AUDIT_BUNDLE_SIGNING_DOMAIN_V2 = b"cuecrux.audit_bundle.v2\x00"


def canonical_manifest_bytes(manifest: dict) -> bytes:
    """Ed25519 sign/verify input selected by ``bundle_format_version`` (v1: field
    order, no tag; v2: domain tag + recursively key-sorted compact JSON). Kept
    identical to ``tools/verify_audit_bundle_v1.py``."""
    signing_manifest = dict(manifest)
    signing_manifest["signature_b64"] = ""
    if manifest.get("bundle_format_version") == 2:
        canonical = json.dumps(
            signing_manifest, separators=(",", ":"), ensure_ascii=False, sort_keys=True
        ).encode("utf-8")
        return AUDIT_BUNDLE_SIGNING_DOMAIN_V2 + canonical
    return json.dumps(signing_manifest, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def write_json(path: Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def build_manifest(events: bytes, receipts: bytes, *, version: int = 1, bundle_id: str = "vector-valid-minimal") -> dict:
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([0x42]) * 32)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    manifest = {
        "bundle_format_version": version,
        "bundle_id": bundle_id,
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


def _zstd_compress(data: bytes) -> bytes:
    """Compress with zstd level 3, preferring the python module over the CLI."""
    try:
        import zstandard as zstd  # type: ignore[import-not-found]
    except Exception:
        zstd = None

    if zstd is not None:
        return zstd.ZstdCompressor(level=3).compress(data)
    if shutil.which("zstd"):
        return subprocess.run(
            ["zstd", "-3", "-c"],
            input=data,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout
    raise RuntimeError(
        "generating .tar.zst vectors requires the python `zstandard` module or the `zstd` CLI; "
        "install with `pip install zstandard`"
    )


def write_archive(dir_path: Path) -> None:
    """Pack the unpacked members of `dir_path` into a deterministic tar.zst."""
    tar_buf = io.BytesIO()
    # GNU format + fixed metadata = reproducible archive across runs.
    with tarfile.open(fileobj=tar_buf, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for member in BUNDLE_MEMBERS:
            payload = (dir_path / member).read_bytes()
            info = tarfile.TarInfo(name=member)
            info.size = len(payload)
            info.mode = 0o644
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(payload))

    (dir_path / ARCHIVE_FILENAME).write_bytes(_zstd_compress(tar_buf.getvalue()))


def write_vector(dir_path: Path, *, manifest: dict, events: bytes, receipts: bytes, expected: dict) -> None:
    dir_path.mkdir(parents=True, exist_ok=True)
    write_json(dir_path / "manifest.json", manifest)
    (dir_path / "events.jsonl").write_bytes(events)
    (dir_path / "receipts.cbor").write_bytes(receipts)
    write_json(dir_path / "expected.json", expected)
    write_archive(dir_path)


def main() -> None:
    events = (
        b'{"fact_id":"f_vector_001","entity":"vector:fixture","key":"status",'
        b'"value":"shipped","confidence":1.0,"stored_at":"2026-06-14T00:00:30Z",'
        b'"tokens":1,"deleted":false,"version":1}\n'
    )
    receipts = b"\x80"
    manifest = build_manifest(events, receipts)

    write_vector(
        VECTORS / "valid-minimal",
        manifest=manifest,
        events=events,
        receipts=receipts,
        expected={"ok": True},
    )

    write_vector(
        VECTORS / "invalid-events-hash",
        manifest=manifest,
        events=events.replace(b"shipped", b"tampered"),
        receipts=receipts,
        expected={"ok": False, "failure_reason_contains": "events.jsonl sha256 mismatch"},
    )

    # v2 (current format): domain-separated, key-canonical signing input. Proves
    # the independent verifier accepts the format the daemon now emits.
    manifest_v2 = build_manifest(events, receipts, version=2, bundle_id="vector-valid-minimal-v2")
    write_vector(
        VECTORS / "valid-minimal-v2",
        manifest=manifest_v2,
        events=events,
        receipts=receipts,
        expected={"ok": True},
    )


if __name__ == "__main__":
    main()
