#!/usr/bin/env python3
"""Independent Audit Bundle vector verifier (formats v1, v2, and v3).

This verifier intentionally supports unpacked vector directories and `.tar.zst`
archives. It mirrors the documented checks without using the Rust implementation,
including all signing formats: v1 (struct-order JSON, no domain tag), v2
(the `cuecrux.audit_bundle.v2` domain tag followed by key-canonical JSON), and
v3 (the equivalent v3 domain plus signed key provenance), so it
can verify the bundles the daemon now emits by default.
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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import load_der_public_key, load_pem_public_key


LEGACY_VERSION = 1
VERSION_2 = 2
CURRENT_VERSION = 3
SUPPORTED_VERSIONS = (LEGACY_VERSION, VERSION_2, CURRENT_VERSION)

# Domain-separation tag prefixed to the v2 signing input. Mirrors
# corecrux_receipts::audit_bundle_v1::AUDIT_BUNDLE_SIGNING_DOMAIN
# (b"cuecrux.audit_bundle.v2\0").
AUDIT_BUNDLE_SIGNING_DOMAIN_V2 = b"cuecrux.audit_bundle.v2\x00"
AUDIT_BUNDLE_SIGNING_DOMAIN_V3 = b"cuecrux.audit_bundle.v3\x00"


def canonical_manifest_bytes(manifest: dict) -> bytes:
    """Reproduce the Ed25519 sign/verify input for the manifest, selected by
    ``bundle_format_version`` (mirrors ``AuditBundleManifestV1::canonical_signing_bytes``):

    * **v1** (legacy): compact JSON in the manifest's own field order, no domain tag.
    * **v2/v3**: the versioned domain tag followed by compact JSON with object keys
      sorted **recursively**, so the signed bytes are independent of field order.
      Python's ``json.dumps(sort_keys=True)`` matches the Rust ``canonical_json_bytes``
      recursive key sort; the manifest carries only strings/integers/nested objects
      (no floats), so number/string formatting is identical across the two.
    """
    signing_manifest = dict(manifest)
    signing_manifest["signature_b64"] = ""
    version = manifest.get("bundle_format_version")
    if version in (VERSION_2, CURRENT_VERSION):
        canonical = json.dumps(
            signing_manifest, separators=(",", ":"), ensure_ascii=False, sort_keys=True
        ).encode("utf-8")
        domain = AUDIT_BUNDLE_SIGNING_DOMAIN_V2 if version == VERSION_2 else AUDIT_BUNDLE_SIGNING_DOMAIN_V3
        return domain + canonical
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
        "witness_proof_count": manifest.get("witness_proof_count", 0) if manifest else 0,
        "witness_proofs_sha256_match": False,
        "witness_proofs_valid": False,
        "witness_root_endorsed": None,
        "failure_reason": reason,
    }


REQUIRED_MEMBERS = ("manifest.json", "events.jsonl", "receipts.cbor")
WITNESS_MEMBER = "witness_proofs.jsonl"


def _parse_sha256_hex(value: str) -> bytes | None:
    """Parse a 32-byte SHA-256 hex digest, tolerating a `sha256:` prefix."""
    if value.startswith("sha256:"):
        value = value[len("sha256:") :]
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return None
    return raw if len(raw) == 32 else None


def _rfc6962_node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def verify_rfc6962_inclusion_proof(
    leaf_hash: str, log_index: int, tree_size: int, root_hash: str, proof: list[str]
) -> bool:
    """Independent mirror of corecrux_receipts::verify_rfc6962_inclusion_proof_v1."""
    if tree_size == 0 or log_index >= tree_size:
        return False
    computed = _parse_sha256_hex(leaf_hash)
    expected_root = _parse_sha256_hex(root_hash)
    if computed is None or expected_root is None:
        return False
    if tree_size == 1:
        return len(proof) == 0 and computed == expected_root
    fn = log_index
    sn = tree_size - 1
    for sibling in proof:
        sib = _parse_sha256_hex(sibling)
        if sib is None or sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            computed = _rfc6962_node_hash(sib, computed)
            while fn != 0 and fn % 2 == 0:
                fn >>= 1
                sn >>= 1
        else:
            computed = _rfc6962_node_hash(computed, sib)
        fn >>= 1
        sn >>= 1
    return sn == 0 and computed == expected_root


def verify_witness_binding(proof: dict) -> bool:
    """Mirror of verify_witness_binding_v1: the entry body hashes to the proof's
    RFC6962 leaf, and the entry's hashedrekord artifact digest equals
    SHA-256(head_hash). True for legacy/unbound proofs (no head/body)."""
    head = proof.get("head_hash") or ""
    body_b64 = proof.get("entry_body_b64") or ""
    if not head and not body_b64:
        return True
    if not head or not body_b64:
        return False
    try:
        body = base64.b64decode(body_b64, validate=True)
    except Exception:  # noqa: BLE001
        return False
    leaf = hashlib.sha256(b"\x00" + body).hexdigest()
    proof_leaf = (proof.get("leaf_hash") or "").removeprefix("sha256:")
    if leaf != proof_leaf:
        return False
    head_bytes = _parse_sha256_hex(head)
    if head_bytes is None:
        return False
    head_digest = hashlib.sha256(head_bytes).hexdigest()
    try:
        entry = json.loads(body)
    except Exception:  # noqa: BLE001
        return False
    value = (((entry.get("spec") or {}).get("data") or {}).get("hash") or {}).get("value", "")
    return value.removeprefix("sha256:") == head_digest


def verify_rekor_checkpoint(checkpoint: str, log_pubkey, expected_root_hex: str) -> bool:
    """Independent mirror of verify_rekor_checkpoint{,_p256}_v1.

    `log_pubkey` is a cryptography public key object — Ed25519 (self-hosted logs)
    or ECDSA P-256 (public-good Rekor). The note signature is keyhash[4]||sig.
    """
    sep = checkpoint.find("\n\n")
    if sep < 0:
        return False
    text = checkpoint[: sep + 1]
    sig_block = checkpoint[sep + 2 :]
    lines = text.split("\n")
    if len(lines) < 3:
        return False
    try:
        root_bytes = base64.b64decode(lines[2].strip(), validate=True)
    except Exception:  # noqa: BLE001
        return False
    expected = _parse_sha256_hex(expected_root_hex.strip())
    if expected is None or root_bytes != expected:
        return False
    for sig_line in sig_block.split("\n"):
        s = sig_line.strip()
        if not s.startswith("— "):
            continue
        parts = s[len("— ") :].rsplit(" ", 1)
        if len(parts) != 2:
            continue
        try:
            raw = base64.b64decode(parts[1].strip(), validate=True)
        except Exception:  # noqa: BLE001
            continue
        if len(raw) <= 4:
            continue
        payload = raw[4:]
        try:
            if isinstance(log_pubkey, ed25519.Ed25519PublicKey):
                log_pubkey.verify(payload, text.encode("utf-8"))
            else:
                log_pubkey.verify(payload, text.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:  # noqa: BLE001
            continue
    return False


def verify_witness_member(
    manifest: dict, witness_bytes: bytes | None, rekor_pubkey: bytes | None = None
) -> tuple[bool, bool, bool | None, str | None]:
    """Re-check the optional witness_proofs.jsonl against the signed manifest.

    Returns (sha256_match, all_proofs_valid, root_endorsed, failure_reason). The
    signed manifest carries the proof count and the member SHA-256, so a stripped
    or mutated member is detectable here without trusting the daemon. When a
    pinned log key is supplied, each proof's checkpoint/SET is verified (the trust
    root); root_endorsed is None when no key was supplied.
    """
    count = manifest.get("witness_proof_count", 0) or 0
    has_member = bool(witness_bytes)
    if count == 0:
        if not has_member:
            return True, True, None, None
        return False, False, None, "witness_proofs.jsonl present but the signed manifest declares none"
    if witness_bytes is None:
        return False, False, None, f"manifest declares {count} witness proof(s) but witness_proofs.jsonl is missing"
    sha = hashlib.sha256(witness_bytes).hexdigest()
    if manifest.get("witness_proofs_sha256") != sha:
        return False, False, None, "witness_proofs.jsonl sha256 mismatch"
    parsed = 0
    for i, line in enumerate(witness_bytes.split(b"\n")):
        if not line.strip():
            continue
        try:
            proof = json.loads(line)
        except Exception as exc:  # noqa: BLE001
            return True, False, None, f"witness proof on line {i} is malformed: {exc}"
        if not verify_rfc6962_inclusion_proof(
            proof.get("leaf_hash", ""),
            int(proof.get("log_index", 0)),
            int(proof.get("tree_size", 0)),
            proof.get("root_hash", ""),
            list(proof.get("inclusion_proof", [])),
        ):
            return True, False, None, f"witness proof {i} (leaf {proof.get('leaf_hash')}) failed RFC6962 verification"
        if not verify_witness_binding(proof):
            return True, False, None, f"witness proof {i} (head {proof.get('head_hash')}) is not bound to its log entry"
        if rekor_pubkey is not None:
            cp = proof.get("checkpoint")
            if not cp or not verify_rekor_checkpoint(cp, rekor_pubkey, proof.get("root_hash", "")):
                return True, True, False, f"witness proof {i} root not endorsed by the pinned log key (checkpoint/SET)"
        parsed += 1
    if parsed != count:
        return True, False, None, f"witness proof count mismatch: manifest {count}, member {parsed}"
    return True, True, (True if rekor_pubkey is not None else None), None


def read_archive_members(path: Path) -> tuple[dict, bytes, bytes, bytes | None]:
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
            if member.name not in REQUIRED_MEMBERS and member.name != WITNESS_MEMBER:
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            members[member.name] = extracted.read()

    missing = [name for name in REQUIRED_MEMBERS if name not in members]
    if missing:
        raise RuntimeError(f"archive missing required member(s): {', '.join(missing)}")
    manifest = json.loads(members["manifest.json"].decode("utf-8"))
    return manifest, members["events.jsonl"], members["receipts.cbor"], members.get(WITNESS_MEMBER)


def read_unpacked_members(path: Path) -> tuple[dict, bytes, bytes, bytes | None] | dict:
    manifest_path = path / "manifest.json"
    events_path = path / "events.jsonl"
    receipts_path = path / "receipts.cbor"

    if not manifest_path.exists():
        return fail(None, "missing manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    if manifest.get("bundle_format_version") not in SUPPORTED_VERSIONS:
        return fail(manifest, f"unsupported bundle_format_version: {manifest.get('bundle_format_version')}")
    if manifest.get("bundle_format_version") == CURRENT_VERSION and manifest.get("key_class") not in {
        "persistent",
        "env",
        "ephemeral",
    }:
        return fail(manifest, "manifest missing or invalid required field: key_class")
    if not events_path.exists():
        return fail(manifest, "missing events.jsonl")
    if not receipts_path.exists():
        return fail(manifest, "missing receipts.cbor")

    witness_path = path / WITNESS_MEMBER
    witness = witness_path.read_bytes() if witness_path.exists() else None
    return manifest, events_path.read_bytes(), receipts_path.read_bytes(), witness


def verify_vector(path: Path, rekor_pubkey: bytes | None = None) -> dict:
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
    manifest, events, receipts, witness = loaded

    if manifest.get("bundle_format_version") not in SUPPORTED_VERSIONS:
        return fail(manifest, f"unsupported bundle_format_version: {manifest.get('bundle_format_version')}")
    if manifest.get("bundle_format_version") == CURRENT_VERSION and manifest.get("key_class") not in {
        "persistent",
        "env",
        "ephemeral",
    }:
        return fail(manifest, "manifest missing or invalid required field: key_class")

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

    witness_sha_match, witness_valid, witness_endorsed, witness_failure = verify_witness_member(
        manifest, witness, rekor_pubkey
    )

    return {
        "ok": witness_sha_match and witness_valid and (witness_endorsed if witness_endorsed is not None else True),
        "bundle_format_version": manifest["bundle_format_version"],
        "bundle_id": manifest["bundle_id"],
        "fact_count": manifest["fact_count"],
        "receipt_count": manifest["receipt_count"],
        "events_jsonl_sha256_match": True,
        "receipts_cbor_sha256_match": True,
        "signature_valid": True,
        "witness_proof_count": manifest.get("witness_proof_count", 0),
        "witness_proofs_sha256_match": witness_sha_match,
        "witness_proofs_valid": witness_valid,
        "witness_root_endorsed": witness_endorsed,
        "failure_reason": witness_failure,
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


def load_pinned_pubkey(path: Path):
    """Load a log public key: a 32-byte file is Ed25519; otherwise a PEM/DER key
    (Ed25519 or ECDSA P-256, the public-good Rekor key form)."""
    raw = path.read_bytes()
    if len(raw) == 32:
        return ed25519.Ed25519PublicKey.from_public_bytes(raw)
    try:
        decoded = base64.b64decode(raw.decode("utf-8").strip(), validate=True)
        if len(decoded) == 32:
            return ed25519.Ed25519PublicKey.from_public_bytes(decoded)
    except Exception:  # noqa: BLE001
        pass
    for loader in (load_pem_public_key, load_der_public_key):
        try:
            return loader(raw)
        except Exception:  # noqa: BLE001
            continue
    raise SystemExit(f"rekor pubkey at {path} is not Ed25519 (32-byte/base64) or P-256 (PEM/DER)")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("vector", type=Path, help="unpacked vector directory or audit-bundle.tar.zst")
    parser.add_argument("--json", action="store_true", help="print report JSON")
    parser.add_argument(
        "--rekor-pubkey",
        type=Path,
        default=None,
        help="pinned log Ed25519 public key (raw 32 bytes or base64) for checkpoint/SET trust-root verification",
    )
    args = parser.parse_args()

    rekor_pubkey = load_pinned_pubkey(args.rekor_pubkey) if args.rekor_pubkey else None
    report = verify_vector(args.vector, rekor_pubkey)
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
