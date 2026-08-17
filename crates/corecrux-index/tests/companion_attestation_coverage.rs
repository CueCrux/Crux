// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! **M5 gate, third clause.** A segment carrying the newly-ported lane companions
//! must have every one of them covered by its `.ccxatt`.
//!
//! `collect_companion_digests` enumerates a segment's companions by **stem**, not by a
//! list of known extensions, so coverage of a new type should hold by construction.
//! "Should hold by construction" is exactly the claim that is worth a test: if the
//! enumeration ever gained an extension allowlist — the shape the storage sweep
//! already has — a new companion would go uncovered, and C8's `invalid` state would
//! never fire for it. An uncovered companion is worse than an unattested one, because
//! the segment still reports a clean `local`/`platform` provenance while carrying
//! bytes nothing signed.
//!
//! The companion bytes here are the real CoreCrux-built fixtures, not filler, so the
//! digests cover what a platform bundle would actually contain.

use corecrux_index::{
    collect_companion_digests, verify_attestation, write_local_attestation, AttestationFailure,
    LocalAttestationRequest, Provenance, TrustRoots,
};
use ed25519_dalek::SigningKey;

/// Every companion this milestone ported, plus the two that shipped before it.
const PORTED_COMPANIONS: [&str; 8] = ["ccxs", "ccxse", "ccxdi", "ccxal", "ccxn", "ccxf", "ccxev", "ccxp"];

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}

/// Lay a segment out on disk exactly as a platform bundle would: a `.ccxseg`, the
/// eight lane companions from the CoreCrux fixtures, and a dense `.ccxe`.
fn lay_out_segment(dir: &std::path::Path, stem: &str) {
    std::fs::write(dir.join(format!("{stem}.ccxseg")), b"sealed segment bytes").expect("write .ccxseg");
    for ext in PORTED_COMPANIONS {
        std::fs::write(dir.join(format!("{stem}.{ext}")), fixture(&format!("corecrux.{ext}")))
            .expect("write companion");
    }
    std::fs::write(dir.join(format!("{stem}.ccxe")), fixture("corecrux-f32.ccxe")).expect("write .ccxe");
}

#[test]
fn every_ported_companion_is_enumerated_for_attestation() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let stem = "seg-00000000000000000042-abcdef";
    lay_out_segment(tmp.path(), stem);

    let digests = collect_companion_digests(tmp.path(), stem).expect("collect digests");
    let exts: Vec<&str> = digests.iter().map(|d| d.ext.as_str()).collect();

    for ext in PORTED_COMPANIONS {
        assert!(
            exts.contains(&ext),
            ".{ext} must be enumerated for attestation; covered = {exts:?}"
        );
    }
    assert!(exts.contains(&"ccxe"), "the dense companion must still be covered");
    assert!(
        !exts.contains(&"ccxseg"),
        "the segment itself is bound by segment_id, not by digest"
    );
    assert_eq!(digests.len(), 9, "eight lane companions plus the dense one");
    assert!(
        digests.iter().all(|d| d.bytes > 0 && d.blake3.len() == 64),
        "every entry needs a real size and a blake3 hex digest"
    );
}

#[test]
fn a_segment_carrying_the_ported_companions_self_signs_and_verifies_as_local() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let stem = "seg-00000000000000000042-abcdef";
    lay_out_segment(tmp.path(), stem);

    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let covered = write_local_attestation(
        tmp.path(),
        stem,
        &LocalAttestationRequest {
            shard_id: 0,
            segment_seq: 42,
            segment_id_hex: stem,
            tenant_id: Some("tenant-a"),
            issued_at: 1_700_000_000,
            producer_fpr: "this-device",
            builder_commit: "test",
        },
        &signing_key,
    )
    .expect("write attestation")
    .expect("a segment with companions must produce one");
    assert_eq!(covered, 9, "all nine companions must be covered");

    let stamp = std::fs::read(tmp.path().join(format!("{stem}.ccxatt"))).expect("read .ccxatt");
    let parsed = corecrux_index::decode_attestation(&stamp).expect("decode");

    let roots = TrustRoots::new().with_local_device("this-device", signing_key.verifying_key().to_bytes());
    let provenance = verify_attestation(&parsed.body, &parsed.signature, &roots, stem, |ext, key| {
        assert!(key.is_none(), "none of these fixtures is model-keyed");
        std::fs::read(tmp.path().join(format!("{stem}.{ext}"))).ok()
    })
    .expect("a self-signed bundle must verify");
    assert_eq!(provenance, Provenance::Local);
}

/// The point of covering a companion is that tampering with it is detected. Flip a
/// byte in each ported companion in turn and assert the stamp refuses — an `invalid`
/// that fails closed in every mode (C8), not a quiet downgrade to `none`.
#[test]
fn tampering_with_any_ported_companion_invalidates_the_attestation() {
    for target in PORTED_COMPANIONS {
        let tmp = tempfile::tempdir().expect("tempdir");
        let stem = "seg-00000000000000000042-abcdef";
        lay_out_segment(tmp.path(), stem);

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        write_local_attestation(
            tmp.path(),
            stem,
            &LocalAttestationRequest {
                shard_id: 0,
                segment_seq: 42,
                segment_id_hex: stem,
                tenant_id: Some("tenant-a"),
                issued_at: 1_700_000_000,
                producer_fpr: "this-device",
                builder_commit: "test",
            },
            &signing_key,
        )
        .expect("write attestation")
        .expect("companions present");

        // Corrupt one byte of one companion, after it was signed.
        let victim = tmp.path().join(format!("{stem}.{target}"));
        let mut bytes = std::fs::read(&victim).expect("read victim");
        bytes[0] ^= 0xFF;
        std::fs::write(&victim, &bytes).expect("write victim");

        let stamp = std::fs::read(tmp.path().join(format!("{stem}.ccxatt"))).expect("read .ccxatt");
        let parsed = corecrux_index::decode_attestation(&stamp).expect("decode");
        let roots = TrustRoots::new().with_local_device("this-device", signing_key.verifying_key().to_bytes());

        let outcome = verify_attestation(&parsed.body, &parsed.signature, &roots, stem, |ext, _key| {
            std::fs::read(tmp.path().join(format!("{stem}.{ext}"))).ok()
        });
        assert!(
            matches!(outcome, Err(AttestationFailure::DigestMismatch { .. })),
            "tampering with .{target} must be caught, got {outcome:?}"
        );
    }
}

/// A segment whose companions are absent must not verify as if they were present.
/// This is the difference between "the platform sent nothing" and "someone deleted
/// the file after it was signed".
#[test]
fn a_missing_ported_companion_is_a_verification_failure_not_a_pass() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let stem = "seg-00000000000000000042-abcdef";
    lay_out_segment(tmp.path(), stem);

    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    write_local_attestation(
        tmp.path(),
        stem,
        &LocalAttestationRequest {
            shard_id: 0,
            segment_seq: 42,
            segment_id_hex: stem,
            tenant_id: Some("tenant-a"),
            issued_at: 1_700_000_000,
            producer_fpr: "this-device",
            builder_commit: "test",
        },
        &signing_key,
    )
    .expect("write attestation")
    .expect("companions present");

    std::fs::remove_file(tmp.path().join(format!("{stem}.ccxn"))).expect("remove .ccxn");

    let stamp = std::fs::read(tmp.path().join(format!("{stem}.ccxatt"))).expect("read .ccxatt");
    let parsed = corecrux_index::decode_attestation(&stamp).expect("decode");
    let roots = TrustRoots::new().with_local_device("this-device", signing_key.verifying_key().to_bytes());

    let outcome = verify_attestation(&parsed.body, &parsed.signature, &roots, stem, |ext, _key| {
        std::fs::read(tmp.path().join(format!("{stem}.{ext}"))).ok()
    });
    assert!(
        outcome.is_err(),
        "a covered companion that vanished must fail, got {outcome:?}"
    );
}
