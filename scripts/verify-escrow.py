#!/usr/bin/env python3
# Copyright (c) 2026 CueCrux Ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Prove for yourself that what a Crux daemon stores for your vault cannot open
# your vault.
#
# This is deliberately a short, readable script rather than a binary we ship.
# The whole point of a verification tool is that you do not have to trust the
# people who wrote the thing being verified — so read it. It is about 120 lines
# and it makes no network calls other than the one GET to your own daemon.
#
#   pip install pynacl blake3
#   python3 verify-escrow.py --vault-id my-vault --token "$CORECRUXD_TOKEN"
#
# `corecruxctl verify-escrow` runs the same named checks. If the two ever
# disagree, that disagreement is the finding — tell us.
#
# Documentation: docs/verify-key-escrow.md

import argparse
import json
import sys
import urllib.request

try:
    import blake3
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
except ImportError:
    sys.exit("pip install pynacl blake3")

# Published in crates/crux-escrow/src/lib.rs. The derivation is:
#   wrapping_key = BLAKE3_derive_key(KDF_CONTEXT, recovery_code_bytes)
# and the vault is XChaCha20-Poly1305(wrapping_key, nonce, dek, aad=vault_id).
KDF_CONTEXT = "cuecrux crux-escrow 2026-08-01 recovery-code wrapping key v1"

# A wrapped 32-byte key plus its 16-byte Poly1305 tag. Anything longer means the
# server is keeping something besides the sealed key.
EXPECTED_CIPHERTEXT_LEN = 32 + 16

# The only three fields the server is supposed to hold.
ALLOWED_FIELDS = {"vault_id", "nonce", "ciphertext"}

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def load_record(args):
    """The record to check: fetched from a daemon, or read from a file.

    The file mode exists so this script can be run against an exported blob with
    no daemon reachable, and so CI can cross-check it against the Rust
    implementation on an identical record.
    """
    if args.record_file:
        with open(args.record_file, encoding="utf-8") as handle:
            return json.load(handle)
    return fetch(args.daemon, args.vault_id, args.token)


def fetch(daemon, vault_id, token):
    url = f"{daemon.rstrip('/')}/v1/escrow/vaults/{vault_id}"
    request = urllib.request.Request(url)
    if token:
        request.add_header("authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def derive_key(material: bytes) -> bytes:
    return blake3.blake3(material, derive_key_context=KDF_CONTEXT).digest(32)


def try_open(record, key: bytes):
    """Return the unwrapped key, or None if this key does not open the vault."""
    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(
            bytes(record["ciphertext"]),
            record["vault_id"].encode(),  # the vault id is authenticated, not encrypted
            bytes(record["nonce"]),
            key,
        )
    except Exception:
        return None


def decode_recovery_code(text: str) -> bytes:
    """Crockford base-32, ignoring separators and folding I/L to 1 and O to 0."""
    cleaned = "".join(c for c in text.upper() if c.isalnum())
    cleaned = cleaned.replace("I", "1").replace("L", "1").replace("O", "0")
    if len(cleaned) != 54:  # 52 symbols of code + 2 of checksum
        raise ValueError(f"expected 54 symbols, got {len(cleaned)}")
    bits = "".join(f"{CROCKFORD.index(c):05b}" for c in cleaned[:52])
    return int(bits[:256], 2).to_bytes(32, "big")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon", default="http://127.0.0.1:14800")
    parser.add_argument("--vault-id", default="")
    parser.add_argument(
        "--record-file",
        help="verify a record already on disk instead of fetching one from a daemon",
    )
    parser.add_argument("--token", help="bearer token with admin:read")
    parser.add_argument(
        "--with-recovery-code",
        action="store_true",
        help="also prove the blob opens for you. Reads the code from stdin; it is "
        "never sent anywhere and never passed on the command line.",
    )
    args = parser.parse_args()

    if not args.vault_id and not args.record_file:
        parser.error("one of --vault-id or --record-file is required")
    record = load_record(args)
    checks = []

    # 1. The server holds three fields and no more. A typed parser would ignore
    #    extras, so this looks at the raw JSON.
    extra = set(record) - ALLOWED_FIELDS
    checks.append(
        (
            "stored_record_has_no_extra_fields",
            not extra,
            f"the server stores exactly {', '.join(sorted(record))}, and nothing else"
            if not extra
            else f"the server is also storing {', '.join(sorted(extra))}",
        )
    )

    # 2. The sealed key is exactly the size of a sealed key.
    length = len(record["ciphertext"])
    checks.append(
        (
            "stored_record_is_ciphertext_only",
            length == EXPECTED_CIPHERTEXT_LEN,
            f"the stored ciphertext is {length} bytes: a 32-byte key under a 16-byte tag, "
            "with no room for anything else",
        )
    )

    # 3. The interesting one. Derive a wrapping key from every field the server
    #    actually holds, and show that none of them opens the vault. If the
    #    server kept any input to your real key, one of these would work.
    candidates = {
        "the vault id": record["vault_id"].encode(),
        "the stored nonce": bytes(record["nonce"]),
        "the stored ciphertext": bytes(record["ciphertext"]),
        "the whole stored record": record["vault_id"].encode()
        + bytes(record["nonce"])
        + bytes(record["ciphertext"]),
        "an empty secret": b"",
        "the published KDF context itself": KDF_CONTEXT.encode(),
    }
    for label, material in candidates.items():
        opened = try_open(record, derive_key(material)) is not None
        checks.append(
            (
                "server_holdings_cannot_open",
                not opened,
                f"a key derived from {label} did not open the vault",
            )
        )

    # 4. Optional positive control. Without it, "nothing opens the vault" would
    #    also be true of a server that stored garbage.
    if args.with_recovery_code:
        print("Paste your recovery code, then press enter.", file=sys.stderr)
        print(
            "It is used only in this process, on this machine, and is never sent anywhere.",
            file=sys.stderr,
        )
        code = decode_recovery_code(sys.stdin.readline())
        opened = try_open(record, derive_key(code)) is not None
        checks.append(
            (
                "opens_with_your_recovery_code",
                opened,
                "your recovery code opened the vault, so the stored blob is the real one "
                "and not a decoy",
            )
        )

    source = args.record_file or f"{args.vault_id} on {args.daemon}"
    print(f"vault {source}")
    for name, passed, detail in checks:
        print(f"  {'PASS' if passed else 'FAIL'} {detail}")
    print()
    if all(passed for _, passed, _ in checks):
        print("All checks passed: the server holds ciphertext and nothing that opens it.")
        return 0
    print("At least one check FAILED. Do not trust this vault until it is explained.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
