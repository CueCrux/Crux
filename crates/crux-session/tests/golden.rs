// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Golden-fixture parity tests.
//!
//! For every fixture in `CueCrux-Shared/packages/session/fixtures/`:
//!   1. decode `plan.cbor` → SessionPlan
//!   2. re-encode → must equal original bytes
//!   3. recompute BLAKE3 over zeroed form → must equal `receipt.hash`
//!   4. recompute canonical JSON → must equal `plan.json`
//!   5. for `verified` mode: recompute hash and verify ed25519 signature
//!
//! The TypeScript mirror at
//! `CueCrux-Shared/packages/session/tests/golden.spec.ts` performs the
//! identical check. Byte equality between the two languages is the
//! Phase-0 gate.

use std::fs;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use serde_json::Value;

use crux_session::plan::{ReceiptMode, SessionPlan};
use crux_session::receipt::{plan_receipt_hash, verify_plan_signature};

fn fixtures_root() -> PathBuf {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .ancestors()
        .nth(3)
        .expect("repo root")
        .join("CueCrux-Shared/packages/session/fixtures")
}

fn all_fixture_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(fixtures_root())
        .expect("read fixtures dir")
        .filter_map(|e| {
            let entry = e.ok()?;
            if entry.file_type().ok()?.is_dir() {
                Some(entry.path())
            } else {
                None
            }
        })
        .collect();
    dirs.sort();
    dirs
}

#[test]
fn every_fixture_round_trips_byte_for_byte() {
    let dirs = all_fixture_dirs();
    assert!(!dirs.is_empty(), "no fixtures found");
    for dir in dirs {
        let cbor_bytes = fs::read(dir.join("plan.cbor"))
            .unwrap_or_else(|_| panic!("read plan.cbor in {dir:?}"));
        let json_bytes = fs::read(dir.join("plan.json"))
            .unwrap_or_else(|_| panic!("read plan.json in {dir:?}"));
        let meta: Value = serde_json::from_slice(
            &fs::read(dir.join("meta.json")).expect("read meta.json"),
        )
        .expect("parse meta.json");

        let plan =
            SessionPlan::from_canonical_cbor(&cbor_bytes).expect("decode fixture cbor");

        let re_encoded = plan.to_canonical_cbor();
        assert_eq!(
            re_encoded,
            cbor_bytes,
            "round-trip bytes mismatch for {:?}",
            dir.file_name()
        );

        let re_json = plan.to_canonical_json();
        let json_str = String::from_utf8(json_bytes).expect("utf8 json");
        assert_eq!(
            re_json,
            json_str,
            "json mismatch for {:?}",
            dir.file_name()
        );

        let expected_hash_hex =
            meta["expected_hash_hex"].as_str().expect("expected_hash_hex");
        let expected_hash =
            hex::decode(expected_hash_hex).expect("decode expected hash");
        let computed_hash = plan_receipt_hash(&plan);
        assert_eq!(
            computed_hash.as_ref(),
            expected_hash.as_slice(),
            "hash mismatch for {:?}",
            dir.file_name()
        );
        assert_eq!(
            plan.receipt.hash.as_ref(),
            expected_hash.as_slice(),
            "fixture receipt.hash diverged from expected for {:?}",
            dir.file_name()
        );

        if plan.receipt.mode == ReceiptMode::Verified {
            let public_key_hex = meta["signer_public_key_hex"]
                .as_str()
                .expect("verified fixture must include signer_public_key_hex");
            let public_key = hex::decode(public_key_hex).expect("decode pubkey");
            verify_plan_signature(&plan, &public_key)
                .unwrap_or_else(|e| panic!("signature verify failed for {dir:?}: {e}"));
        }
    }
}

#[test]
fn tamper_breaks_hash_verification() {
    let dir = fixtures_root().join("003-hosted-free");
    let cbor_bytes = fs::read(dir.join("plan.cbor")).expect("read plan.cbor");
    let mut plan = SessionPlan::from_canonical_cbor(&cbor_bytes).expect("decode");
    // Tamper with a capability's `prefer` field — should change the plan hash.
    plan.capability_graph[0].prefer = "mcp".to_string();
    let new_hash = plan_receipt_hash(&plan);
    assert_ne!(
        new_hash.as_ref(),
        plan.receipt.hash.as_ref(),
        "tampering with prefer must change the hash"
    );
}

#[test]
fn zeroed_receipt_hashing_is_idempotent() {
    let dir = fixtures_root().join("001-ce-minimal");
    let cbor_bytes = fs::read(dir.join("plan.cbor")).expect("read plan.cbor");
    let plan = SessionPlan::from_canonical_cbor(&cbor_bytes).expect("decode");
    // Compute hash twice — canonical encoding is deterministic, hash is
    // deterministic, so two calls must match.
    let a = plan_receipt_hash(&plan);
    let b = plan_receipt_hash(&plan);
    assert_eq!(a, b);
}

#[test]
fn signature_verification_rejects_wrong_key() {
    let dir = fixtures_root().join("003-hosted-free");
    let cbor_bytes = fs::read(dir.join("plan.cbor")).expect("read plan.cbor");
    let plan = SessionPlan::from_canonical_cbor(&cbor_bytes).expect("decode");
    let wrong_key = SigningKey::from_bytes(&[2u8; 32]).verifying_key().to_bytes();
    let err = verify_plan_signature(&plan, &wrong_key);
    assert!(err.is_err(), "wrong key must fail");
}
