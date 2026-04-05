// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use base64::Engine as _;
use ed25519_dalek::Signer as _;
use ed25519_dalek::SigningKey;
use rand::{RngCore, SeedableRng};

use crate::export_v1::{
    build_receipt_export_v1, BuildReceiptExportInput, ExportFormatV1, ExportRedactionV1,
    ReceiptEventHeaderRefV1, ReceiptExportIncludeV1, ReceiptExportOptionsV1,
};
use crate::keyring_v1::{Ed25519KeyEntryV1, Ed25519KeyRingV1};
use crate::verify_v1::{verify_receipt_v1, ReceiptSigV1, VerifyReceiptInput};

fn encode_sig_cbor(sig: &ReceiptSigV1) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(sig, &mut out).expect("encode cbor");
    out
}

fn encode_body_cbor() -> Vec<u8> {
    // Minimal, valid CBOR. Producers own canonicalization; CoreCrux is bytes-first.
    let v = ciborium::value::Value::Map(vec![
        (
            ciborium::value::Value::Text("schema".to_string()),
            ciborium::value::Value::Text("cuecrux.receipt.body.v1".to_string()),
        ),
        (
            ciborium::value::Value::Text("receipt_id".to_string()),
            ciborium::value::Value::Text("00000000-0000-0000-0000-000000000001".to_string()),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&v, &mut out).expect("encode body");
    out
}

fn encode_body_cbor_with_retrieval_trace(candidate_digest: &str) -> Vec<u8> {
    use ciborium::value::Value;

    let lanes_used = Value::Array(vec![
        Value::Map(vec![(
            Value::Text("lane_key".to_string()),
            Value::Text("laneA".to_string()),
        )]),
        Value::Map(vec![(
            Value::Text("lane_key".to_string()),
            Value::Text("laneB".to_string()),
        )]),
    ]);

    let candidates = Value::Array(vec![
        Value::Map(vec![
            (
                Value::Text("chunk_id".to_string()),
                Value::Text("CHUNK1".to_string()),
            ),
            (Value::Text("sparse_score".to_string()), Value::Float(0.1)),
            (
                Value::Text("lane_scores".to_string()),
                Value::Map(vec![
                    (Value::Text("laneA".to_string()), Value::Float(0.2)),
                    (Value::Text("laneB".to_string()), Value::Null),
                ]),
            ),
            (Value::Text("fusion_score".to_string()), Value::Float(0.3)),
            (Value::Text("priors_score".to_string()), Value::Null),
            (Value::Text("anchor_score".to_string()), Value::Float(0.0)),
            (
                Value::Text("rerank_score".to_string()),
                Value::Float(1.234567),
            ),
        ]),
        Value::Map(vec![
            (
                Value::Text("chunk_id".to_string()),
                Value::Text("chunk2".to_string()),
            ),
            (Value::Text("sparse_score".to_string()), Value::Null),
            (
                Value::Text("lane_scores".to_string()),
                Value::Map(vec![
                    (Value::Text("laneA".to_string()), Value::Float(-0.1)),
                    (Value::Text("laneB".to_string()), Value::Float(0.0)),
                ]),
            ),
            (Value::Text("fusion_score".to_string()), Value::Null),
            (Value::Text("priors_score".to_string()), Value::Float(0.2)),
            (Value::Text("anchor_score".to_string()), Value::Null),
            (Value::Text("rerank_score".to_string()), Value::Null),
        ]),
    ]);

    let retrieval_trace = Value::Map(vec![
        (Value::Text("lanes_used".to_string()), lanes_used),
        (Value::Text("candidates".to_string()), candidates),
        (
            Value::Text("candidate_digest".to_string()),
            Value::Text(candidate_digest.to_string()),
        ),
    ]);

    let v = Value::Map(vec![
        (
            Value::Text("schema".to_string()),
            Value::Text("cuecrux.receipt.body.v1".to_string()),
        ),
        (
            Value::Text("receipt_id".to_string()),
            Value::Text("00000000-0000-0000-0000-000000000001".to_string()),
        ),
        (Value::Text("retrieval_trace".to_string()), retrieval_trace),
    ]);

    let mut out = Vec::new();
    ciborium::ser::into_writer(&v, &mut out).expect("encode body");
    out
}

#[test]
fn extract_linked_receipts_finds_top_level_and_action_block() {
    // top-level
    let v = ciborium::value::Value::Map(vec![(
        ciborium::value::Value::Text("linked_receipts".to_string()),
        ciborium::value::Value::Array(vec![
            ciborium::value::Value::Text("r1".to_string()),
            ciborium::value::Value::Text("r2".to_string()),
        ]),
    )]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&v, &mut bytes).expect("encode");
    let out = crate::extract_linked_receipts_v1(&bytes).expect("parse");
    assert_eq!(out, vec!["r1".to_string(), "r2".to_string()]);

    // nested under action
    let v = ciborium::value::Value::Map(vec![(
        ciborium::value::Value::Text("action".to_string()),
        ciborium::value::Value::Map(vec![(
            ciborium::value::Value::Text("linked_receipts".to_string()),
            ciborium::value::Value::Array(vec![ciborium::value::Value::Text("r3".to_string())]),
        )]),
    )]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&v, &mut bytes).expect("encode");
    let out = crate::extract_linked_receipts_v1(&bytes).expect("parse");
    assert_eq!(out, vec!["r3".to_string()]);
}

#[test]
fn verify_tier2_candidate_digest_recompute_sets_match_flag() {
    let receipt_id = "00000000-0000-0000-0000-000000000001";
    let tenant_id = "tenant-a";

    // Verified against the Engine reference implementation for the same inputs.
    let digest = "blake3:hex:ce0d4e988c55acfb0315f258b94295e5c98f259dea171c19688b38f46b96d626";

    let body = encode_body_cbor_with_retrieval_trace(digest);
    let stored_hash = *blake3::hash(&body).as_bytes();

    let build = corecrux_types::BuildInfo {
        version: "0.0.1".to_string(),
        commit: "deadbeef".to_string(),
    };

    let report = verify_receipt_v1(VerifyReceiptInput {
        tenant_id,
        receipt_id,
        body_bytes: &body,
        stored_body_payload_hash: stored_hash,
        sig_bytes: None,
        keyring: None,
        verified_at: "2026-02-09T00:00:01Z",
        verifier_build: &build,
        recompute_candidate_digest: true,
    })
    .expect("verify");

    assert!(report.trace_checks.retrieval_trace_present);
    assert!(report.trace_checks.lanes_used_present);
    assert!(report.trace_checks.candidates_present);
    assert!(report.trace_checks.candidate_digest_present);
    assert_eq!(
        report.trace_checks.candidate_digest_matches_recompute,
        Some(true)
    );
    assert_eq!(
        report
            .trace_summary
            .as_ref()
            .and_then(|s| s.candidate_digest.as_deref()),
        Some(digest)
    );
}

#[test]
fn verify_tier2_candidate_digest_recompute_reports_mismatch() {
    let receipt_id = "00000000-0000-0000-0000-000000000001";
    let tenant_id = "tenant-a";

    let body = encode_body_cbor_with_retrieval_trace(
        "blake3:hex:0000000000000000000000000000000000000000000000000000000000000000",
    );
    let stored_hash = *blake3::hash(&body).as_bytes();

    let build = corecrux_types::BuildInfo {
        version: "0.0.1".to_string(),
        commit: "deadbeef".to_string(),
    };

    let report = verify_receipt_v1(VerifyReceiptInput {
        tenant_id,
        receipt_id,
        body_bytes: &body,
        stored_body_payload_hash: stored_hash,
        sig_bytes: None,
        keyring: None,
        verified_at: "2026-02-09T00:00:01Z",
        verifier_build: &build,
        recompute_candidate_digest: true,
    })
    .expect("verify");

    assert!(report.trace_checks.retrieval_trace_present);
    assert!(report.trace_checks.lanes_used_present);
    assert!(report.trace_checks.candidates_present);
    assert!(report.trace_checks.candidate_digest_present);
    assert_eq!(
        report.trace_checks.candidate_digest_matches_recompute,
        Some(false)
    );
    assert_eq!(
        report
            .trace_summary
            .as_ref()
            .and_then(|s| s.candidate_digest.as_deref()),
        Some("blake3:hex:0000000000000000000000000000000000000000000000000000000000000000")
    );
}

#[test]
fn verify_ed25519_ok_and_zip_deterministic() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(123);
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    let sk = SigningKey::from_bytes(&sk_bytes);
    let vk = sk.verifying_key();

    let key_id = "k1";
    let keyring = Ed25519KeyRingV1 {
        v: 1,
        keys: vec![Ed25519KeyEntryV1 {
            key_id: key_id.to_string(),
            pub_key_base64: base64::engine::general_purpose::STANDARD.encode(vk.as_bytes()),
        }],
    };

    let receipt_id = "00000000-0000-0000-0000-000000000001";
    let tenant_id = "tenant-a";

    let body = encode_body_cbor();
    let stored_hash = *blake3::hash(&body).as_bytes();
    let sig64 = sk.sign(&body).to_bytes().to_vec();

    let sig = ReceiptSigV1 {
        schema: "cuecrux.receipt.sig.v1".to_string(),
        receipt_id: receipt_id.to_string(),
        alg: "ed25519".to_string(),
        key_id: key_id.to_string(),
        signed_at: "2026-02-09T00:00:00Z".to_string(),
        signature: sig64,
        signed_payload_hash: stored_hash.to_vec(),
    };
    let sig_bytes = encode_sig_cbor(&sig);

    let build = corecrux_types::BuildInfo {
        version: "0.0.1".to_string(),
        commit: "deadbeef".to_string(),
    };

    let report = verify_receipt_v1(VerifyReceiptInput {
        tenant_id,
        receipt_id,
        body_bytes: &body,
        stored_body_payload_hash: stored_hash,
        sig_bytes: Some(&sig_bytes),
        keyring: Some(&keyring),
        verified_at: "2026-02-09T00:00:01Z",
        verifier_build: &build,
        recompute_candidate_digest: false,
    })
    .expect("verify");

    assert!(report.signature_valid);
    assert_eq!(report.error_code, "OK");
    assert!(report.integrity.payload_hash_matches);
    assert!(report.integrity.canonical_bytes_parse_ok);

    let bundle1 = build_receipt_export_v1(
        BuildReceiptExportInput {
            generated_at: "2026-02-09T00:00:01Z",
            tenant_id,
            receipt_id,
            build: &build,
            body_bytes: &body,
            sig_bytes: &sig_bytes,
            verification_report: &report,
            body_payload_hash_hex: &report.payload_hash_hex,
            sig_event_ref: "seq=1",
            event_headers: vec![
                ReceiptEventHeaderRefV1 {
                    header_hash: "hh_body".to_string(),
                    payload_hash: report.payload_hash_hex.clone(),
                    seq: 0,
                    event_id: "evt-body".to_string(),
                    occurred_at: "2026-02-09T00:00:00Z".to_string(),
                },
                ReceiptEventHeaderRefV1 {
                    header_hash: "hh_sig".to_string(),
                    payload_hash: blake3::hash(&sig_bytes).to_hex().to_string(),
                    seq: 1,
                    event_id: "evt-sig".to_string(),
                    occurred_at: "2026-02-09T00:00:00Z".to_string(),
                },
            ],
            trace_summary_json: None,
            subject_links_json: None,
            lineage_json: None,
        },
        &ReceiptExportOptionsV1 {
            format: ExportFormatV1::Zip,
            redaction: ExportRedactionV1::TenantSafe,
            include: Vec::new(),
        },
    )
    .expect("export");

    let bundle2 = build_receipt_export_v1(
        BuildReceiptExportInput {
            generated_at: "2026-02-09T00:00:01Z",
            tenant_id,
            receipt_id,
            build: &build,
            body_bytes: &body,
            sig_bytes: &sig_bytes,
            verification_report: &report,
            body_payload_hash_hex: &report.payload_hash_hex,
            sig_event_ref: "seq=1",
            event_headers: vec![
                ReceiptEventHeaderRefV1 {
                    header_hash: "hh_body".to_string(),
                    payload_hash: report.payload_hash_hex.clone(),
                    seq: 0,
                    event_id: "evt-body".to_string(),
                    occurred_at: "2026-02-09T00:00:00Z".to_string(),
                },
                ReceiptEventHeaderRefV1 {
                    header_hash: "hh_sig".to_string(),
                    payload_hash: blake3::hash(&sig_bytes).to_hex().to_string(),
                    seq: 1,
                    event_id: "evt-sig".to_string(),
                    occurred_at: "2026-02-09T00:00:00Z".to_string(),
                },
            ],
            trace_summary_json: None,
            subject_links_json: None,
            lineage_json: None,
        },
        &ReceiptExportOptionsV1 {
            format: ExportFormatV1::Zip,
            redaction: ExportRedactionV1::TenantSafe,
            include: Vec::new(),
        },
    )
    .expect("export");

    assert_eq!(bundle1.archive_bytes, bundle2.archive_bytes);
}

#[test]
fn export_includes_lineage_when_requested() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(123);
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    let sk = SigningKey::from_bytes(&sk_bytes);
    let vk = sk.verifying_key();

    let key_id = "k1";
    let keyring = Ed25519KeyRingV1 {
        v: 1,
        keys: vec![Ed25519KeyEntryV1 {
            key_id: key_id.to_string(),
            pub_key_base64: base64::engine::general_purpose::STANDARD.encode(vk.as_bytes()),
        }],
    };

    let receipt_id = "00000000-0000-0000-0000-000000000010";
    let tenant_id = "tenant-a";

    let body = encode_body_cbor();
    let stored_hash = *blake3::hash(&body).as_bytes();
    let sig64 = sk.sign(&body).to_bytes().to_vec();

    let sig = ReceiptSigV1 {
        schema: "cuecrux.receipt.sig.v1".to_string(),
        receipt_id: receipt_id.to_string(),
        alg: "ed25519".to_string(),
        key_id: key_id.to_string(),
        signed_at: "2026-02-09T00:00:00Z".to_string(),
        signature: sig64,
        signed_payload_hash: stored_hash.to_vec(),
    };
    let sig_bytes = encode_sig_cbor(&sig);

    let build = corecrux_types::BuildInfo {
        version: "0.0.1".to_string(),
        commit: "deadbeef".to_string(),
    };

    let report = verify_receipt_v1(VerifyReceiptInput {
        tenant_id,
        receipt_id,
        body_bytes: &body,
        stored_body_payload_hash: stored_hash,
        sig_bytes: Some(&sig_bytes),
        keyring: Some(&keyring),
        verified_at: "2026-02-09T00:00:01Z",
        verifier_build: &build,
        recompute_candidate_digest: false,
    })
    .expect("verify");

    let lineage =
        br#"{"schema":"cuecrux.receipt.lineage.v1","parse_ok":true,"linked_receipts":[]}"#;
    let bundle = build_receipt_export_v1(
        BuildReceiptExportInput {
            generated_at: "2026-02-09T00:00:01Z",
            tenant_id,
            receipt_id,
            build: &build,
            body_bytes: &body,
            sig_bytes: &sig_bytes,
            verification_report: &report,
            body_payload_hash_hex: &report.payload_hash_hex,
            sig_event_ref: "seq=1",
            event_headers: vec![ReceiptEventHeaderRefV1 {
                header_hash: "hh_body".to_string(),
                payload_hash: report.payload_hash_hex.clone(),
                seq: 0,
                event_id: "evt-body".to_string(),
                occurred_at: "2026-02-09T00:00:00Z".to_string(),
            }],
            trace_summary_json: None,
            subject_links_json: None,
            lineage_json: Some(lineage),
        },
        &ReceiptExportOptionsV1 {
            format: ExportFormatV1::Zip,
            redaction: ExportRedactionV1::TenantSafe,
            include: vec![ReceiptExportIncludeV1::LinkedReceipts],
        },
    )
    .expect("export");

    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bundle.archive_bytes)).expect("zip");
    let _ = zip.by_name("links/lineage.json").expect("lineage file");
}

#[test]
fn verify_body_corruption_surfaces_hash_mismatch() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(456);
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    let sk = SigningKey::from_bytes(&sk_bytes);
    let vk = sk.verifying_key();

    let keyring = Ed25519KeyRingV1 {
        v: 1,
        keys: vec![Ed25519KeyEntryV1 {
            key_id: "k1".to_string(),
            pub_key_base64: base64::engine::general_purpose::STANDARD.encode(vk.as_bytes()),
        }],
    };

    let receipt_id = "00000000-0000-0000-0000-000000000002";
    let tenant_id = "tenant-a";

    let mut body = encode_body_cbor();
    let stored_hash = *blake3::hash(&body).as_bytes();
    let sig64 = sk.sign(&body).to_bytes().to_vec();

    // Corrupt a byte in body after the header payloadHash has been computed/stored.
    body[0] ^= 0x55;

    let sig = ReceiptSigV1 {
        schema: "cuecrux.receipt.sig.v1".to_string(),
        receipt_id: receipt_id.to_string(),
        alg: "ed25519".to_string(),
        key_id: "k1".to_string(),
        signed_at: "2026-02-09T00:00:00Z".to_string(),
        signature: sig64,
        signed_payload_hash: stored_hash.to_vec(),
    };
    let sig_bytes = encode_sig_cbor(&sig);

    let build = corecrux_types::BuildInfo {
        version: "0.0.1".to_string(),
        commit: "deadbeef".to_string(),
    };

    let report = verify_receipt_v1(VerifyReceiptInput {
        tenant_id,
        receipt_id,
        body_bytes: &body,
        stored_body_payload_hash: stored_hash,
        sig_bytes: Some(&sig_bytes),
        keyring: Some(&keyring),
        verified_at: "2026-02-09T00:00:01Z",
        verifier_build: &build,
        recompute_candidate_digest: false,
    })
    .expect("verify");

    assert!(!report.integrity.payload_hash_matches);
    assert_eq!(report.error_code, "BODY_HASH_MISMATCH");
}

#[test]
fn verify_invalid_signature_returns_sig_invalid_when_hash_matches() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(789);
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    let sk = SigningKey::from_bytes(&sk_bytes);
    let vk = sk.verifying_key();

    let keyring = Ed25519KeyRingV1 {
        v: 1,
        keys: vec![Ed25519KeyEntryV1 {
            key_id: "k1".to_string(),
            pub_key_base64: base64::engine::general_purpose::STANDARD.encode(vk.as_bytes()),
        }],
    };

    let receipt_id = "00000000-0000-0000-0000-000000000003";
    let tenant_id = "tenant-a";

    let body = encode_body_cbor();
    let stored_hash = *blake3::hash(&body).as_bytes();
    let mut sig64 = sk.sign(&body).to_bytes().to_vec();
    // Flip one bit: signature should fail while payload hash still matches.
    sig64[0] ^= 0x01;

    let sig = ReceiptSigV1 {
        schema: "cuecrux.receipt.sig.v1".to_string(),
        receipt_id: receipt_id.to_string(),
        alg: "ed25519".to_string(),
        key_id: "k1".to_string(),
        signed_at: "2026-02-09T00:00:00Z".to_string(),
        signature: sig64,
        signed_payload_hash: stored_hash.to_vec(),
    };
    let sig_bytes = encode_sig_cbor(&sig);

    let build = corecrux_types::BuildInfo {
        version: "0.0.1".to_string(),
        commit: "deadbeef".to_string(),
    };

    let report = verify_receipt_v1(VerifyReceiptInput {
        tenant_id,
        receipt_id,
        body_bytes: &body,
        stored_body_payload_hash: stored_hash,
        sig_bytes: Some(&sig_bytes),
        keyring: Some(&keyring),
        verified_at: "2026-02-09T00:00:01Z",
        verifier_build: &build,
        recompute_candidate_digest: false,
    })
    .expect("verify");

    assert!(report.integrity.payload_hash_matches);
    assert!(!report.signature_valid);
    assert_eq!(report.error_code, "SIG_INVALID");
}

#[test]
fn verify_key_rotation_ok_and_missing_key_reports_key_not_found() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(321);

    let mut sk1_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk1_bytes);
    let sk1 = SigningKey::from_bytes(&sk1_bytes);

    let mut sk2_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk2_bytes);
    let sk2 = SigningKey::from_bytes(&sk2_bytes);

    let vk1 = sk1.verifying_key();
    let vk2 = sk2.verifying_key();

    let keyring = Ed25519KeyRingV1 {
        v: 1,
        keys: vec![
            Ed25519KeyEntryV1 {
                key_id: "k1".to_string(),
                pub_key_base64: base64::engine::general_purpose::STANDARD.encode(vk1.as_bytes()),
            },
            Ed25519KeyEntryV1 {
                key_id: "k2".to_string(),
                pub_key_base64: base64::engine::general_purpose::STANDARD.encode(vk2.as_bytes()),
            },
        ],
    };

    let receipt_id = "00000000-0000-0000-0000-000000000004";
    let tenant_id = "tenant-a";

    let body = encode_body_cbor();
    let stored_hash = *blake3::hash(&body).as_bytes();

    let build = corecrux_types::BuildInfo {
        version: "0.0.1".to_string(),
        commit: "deadbeef".to_string(),
    };

    // Rotate to k2: verification should still succeed.
    let sig_k2 = ReceiptSigV1 {
        schema: "cuecrux.receipt.sig.v1".to_string(),
        receipt_id: receipt_id.to_string(),
        alg: "ed25519".to_string(),
        key_id: "k2".to_string(),
        signed_at: "2026-02-09T00:00:00Z".to_string(),
        signature: sk2.sign(&body).to_bytes().to_vec(),
        signed_payload_hash: stored_hash.to_vec(),
    };
    let sig_k2_bytes = encode_sig_cbor(&sig_k2);

    let report_ok = verify_receipt_v1(VerifyReceiptInput {
        tenant_id,
        receipt_id,
        body_bytes: &body,
        stored_body_payload_hash: stored_hash,
        sig_bytes: Some(&sig_k2_bytes),
        keyring: Some(&keyring),
        verified_at: "2026-02-09T00:00:01Z",
        verifier_build: &build,
        recompute_candidate_digest: false,
    })
    .expect("verify");
    assert!(report_ok.signature_valid);
    assert_eq!(report_ok.error_code, "OK");

    // Unknown key id should surface KEY_NOT_FOUND with low-cardinality error code.
    let sig_missing_key = ReceiptSigV1 {
        schema: "cuecrux.receipt.sig.v1".to_string(),
        receipt_id: receipt_id.to_string(),
        alg: "ed25519".to_string(),
        key_id: "k-missing".to_string(),
        signed_at: "2026-02-09T00:00:00Z".to_string(),
        signature: sk1.sign(&body).to_bytes().to_vec(),
        signed_payload_hash: stored_hash.to_vec(),
    };
    let sig_missing_key_bytes = encode_sig_cbor(&sig_missing_key);

    let report_missing = verify_receipt_v1(VerifyReceiptInput {
        tenant_id,
        receipt_id,
        body_bytes: &body,
        stored_body_payload_hash: stored_hash,
        sig_bytes: Some(&sig_missing_key_bytes),
        keyring: Some(&keyring),
        verified_at: "2026-02-09T00:00:01Z",
        verifier_build: &build,
        recompute_candidate_digest: false,
    })
    .expect("verify");
    assert!(!report_missing.signature_valid);
    assert_eq!(report_missing.error_code, "KEY_NOT_FOUND");
}

// ---------------------------------------------------------------------------
// store_v1 tests
// ---------------------------------------------------------------------------

#[test]
fn verification_report_path_deterministic_and_hashes_tenant() {
    use crate::store_v1::verification_report_path_v1;
    use std::path::Path;

    let shard = Path::new("/tmp/shard-0");
    let p1 = verification_report_path_v1(shard, "tenant-a", "receipt-001");
    let p2 = verification_report_path_v1(shard, "tenant-a", "receipt-001");
    assert_eq!(p1, p2, "same inputs must yield same path");

    // Tenant ID is hashed, not used verbatim.
    let path_str = p1.to_str().unwrap();
    assert!(!path_str.contains("tenant-a"), "raw tenant_id must not appear in path");
    assert!(path_str.contains("tenant-"), "path should contain 'tenant-' prefix");
    assert!(path_str.ends_with("receipt-001.json"));

    // Different tenants get different paths.
    let p3 = verification_report_path_v1(shard, "tenant-b", "receipt-001");
    assert_ne!(p1, p3, "different tenants must get different paths");
}

#[test]
fn store_and_load_verification_report_roundtrip() {
    use crate::store_v1::{load_verification_report_v1, store_verification_report_v1};
    use crate::verify_v1::{
        VerificationIntegrityV1, VerificationReportV1, VerificationSigInfoV1,
        VerificationTraceChecksV1,
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let shard = tmp.path();

    let report = VerificationReportV1 {
        schema: "cuecrux.receipt.verify.v1".to_string(),
        receipt_id: "r-123".to_string(),
        tenant_id: "t-abc".to_string(),
        payload_hash_hex: "deadbeef".repeat(8),
        signature: VerificationSigInfoV1 {
            alg: "ed25519".to_string(),
            key_id: Some("k1".to_string()),
        },
        integrity: VerificationIntegrityV1 {
            payload_hash_matches: true,
            canonical_bytes_parse_ok: true,
        },
        trace_checks: VerificationTraceChecksV1::default(),
        trace_summary: None,
        signature_valid: true,
        pubkey_fingerprint: Some("fp123".to_string()),
        error_code: "OK".to_string(),
        error_message: None,
        verified_at: "2026-01-01T00:00:00Z".to_string(),
        verifier_build: "0.0.1@abc".to_string(),
    };

    let path = store_verification_report_v1(shard, &report).expect("store");
    assert!(path.exists());

    let loaded = load_verification_report_v1(shard, "t-abc", "r-123")
        .expect("load")
        .expect("should exist");
    assert_eq!(loaded.receipt_id, "r-123");
    assert_eq!(loaded.tenant_id, "t-abc");
    assert!(loaded.signature_valid);
    assert_eq!(loaded.error_code, "OK");
}

#[test]
fn load_nonexistent_returns_none() {
    use crate::store_v1::load_verification_report_v1;

    let tmp = tempfile::tempdir().expect("tempdir");
    let result = load_verification_report_v1(tmp.path(), "t-missing", "r-missing")
        .expect("load should not fail");
    assert!(result.is_none());
}

#[test]
fn load_report_with_mismatched_tenant_returns_error() {
    use crate::store_v1::{
        load_verification_report_v1, store_verification_report_v1, verification_report_path_v1,
    };
    use crate::verify_v1::{
        VerificationIntegrityV1, VerificationReportV1, VerificationSigInfoV1,
        VerificationTraceChecksV1,
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let shard = tmp.path();

    // Store a report for tenant-a.
    let report = VerificationReportV1 {
        schema: "cuecrux.receipt.verify.v1".to_string(),
        receipt_id: "r-1".to_string(),
        tenant_id: "tenant-a".to_string(),
        payload_hash_hex: "aa".repeat(32),
        signature: VerificationSigInfoV1 {
            alg: "ed25519".to_string(),
            key_id: None,
        },
        integrity: VerificationIntegrityV1 {
            payload_hash_matches: true,
            canonical_bytes_parse_ok: true,
        },
        trace_checks: VerificationTraceChecksV1::default(),
        trace_summary: None,
        signature_valid: false,
        pubkey_fingerprint: None,
        error_code: "SIG_MISSING".to_string(),
        error_message: None,
        verified_at: "2026-01-01T00:00:00Z".to_string(),
        verifier_build: "0.0.1@abc".to_string(),
    };
    store_verification_report_v1(shard, &report).expect("store");

    // Manually copy the file to tenant-b's path to simulate a collision.
    let src = verification_report_path_v1(shard, "tenant-a", "r-1");
    let dst = verification_report_path_v1(shard, "tenant-b", "r-1");
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::copy(&src, &dst).unwrap();

    // Loading with tenant-b should fail because the stored tenant_id is tenant-a.
    let err = load_verification_report_v1(shard, "tenant-b", "r-1");
    assert!(err.is_err() || matches!(err, Ok(Some(_))));
    // Actually the code checks tenant mismatch and returns Err.
    match load_verification_report_v1(shard, "tenant-b", "r-1") {
        Err(e) => assert!(e.to_string().contains("mismatch")),
        _ => panic!("expected mismatch error"),
    }
}

// ---------------------------------------------------------------------------
// subject_index_v1 tests
// ---------------------------------------------------------------------------

#[test]
fn subject_resolve_mode_parse() {
    use crate::subject_index_v1::SubjectResolveModeV1;

    assert_eq!(
        SubjectResolveModeV1::parse("latest"),
        Some(SubjectResolveModeV1::Latest)
    );
    assert_eq!(
        SubjectResolveModeV1::parse("verified"),
        Some(SubjectResolveModeV1::Verified)
    );
    assert_eq!(
        SubjectResolveModeV1::parse("audit"),
        Some(SubjectResolveModeV1::Audit)
    );
    assert_eq!(SubjectResolveModeV1::parse("unknown"), None);
    assert_eq!(SubjectResolveModeV1::parse(""), None);
}

#[test]
fn subject_index_path_deterministic_and_hashes_ids() {
    use crate::subject_index_v1::subject_index_path_v1;
    use std::path::Path;

    let root = Path::new("/tmp/idx");
    let p1 = subject_index_path_v1(root, "t1", "answer", "subj-42");
    let p2 = subject_index_path_v1(root, "t1", "answer", "subj-42");
    assert_eq!(p1, p2);

    // Neither raw tenant nor raw subject should appear in the path.
    let s = p1.to_str().unwrap();
    assert!(!s.contains("subj-42"));
    assert!(!s.contains("/t1/"));
    assert!(s.contains("answer")); // kind is used verbatim

    // Different subjects get different paths.
    let p3 = subject_index_path_v1(root, "t1", "answer", "subj-99");
    assert_ne!(p1, p3);
}

#[test]
fn update_and_resolve_subject_index_roundtrip() {
    use crate::subject_index_v1::{
        resolve_subject_receipt_id_v1, update_subject_index_v1, SubjectResolveModeV1,
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();

    // Create initial entry (light mode).
    update_subject_index_v1(root, "t1", "answer", "s1", "r-100", "light", "2026-01-01T00:00:00Z")
        .expect("create");

    let latest = resolve_subject_receipt_id_v1(root, "t1", "answer", "s1", SubjectResolveModeV1::Latest)
        .expect("resolve")
        .expect("should exist");
    assert_eq!(latest, "r-100");

    // Verified mode should be None.
    let verified = resolve_subject_receipt_id_v1(root, "t1", "answer", "s1", SubjectResolveModeV1::Verified)
        .expect("resolve");
    assert!(verified.is_none());

    // Add a verified entry with a later timestamp.
    update_subject_index_v1(root, "t1", "answer", "s1", "r-200", "verified", "2026-01-02T00:00:00Z")
        .expect("update");

    let latest2 = resolve_subject_receipt_id_v1(root, "t1", "answer", "s1", SubjectResolveModeV1::Latest)
        .expect("resolve")
        .expect("should exist");
    assert_eq!(latest2, "r-200");

    let verified2 = resolve_subject_receipt_id_v1(root, "t1", "answer", "s1", SubjectResolveModeV1::Verified)
        .expect("resolve")
        .expect("should exist");
    assert_eq!(verified2, "r-200");

    // Audit mode should still be None.
    let audit = resolve_subject_receipt_id_v1(root, "t1", "answer", "s1", SubjectResolveModeV1::Audit)
        .expect("resolve");
    assert!(audit.is_none());
}

#[test]
fn subject_index_latest_not_overwritten_by_older_timestamp() {
    use crate::subject_index_v1::{
        resolve_subject_receipt_id_v1, update_subject_index_v1, SubjectResolveModeV1,
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();

    update_subject_index_v1(root, "t1", "answer", "s1", "r-new", "light", "2026-06-01T00:00:00Z")
        .expect("create");
    // Insert an older entry — should NOT overwrite latest.
    update_subject_index_v1(root, "t1", "answer", "s1", "r-old", "light", "2026-01-01T00:00:00Z")
        .expect("update");

    let latest = resolve_subject_receipt_id_v1(root, "t1", "answer", "s1", SubjectResolveModeV1::Latest)
        .expect("resolve")
        .expect("should exist");
    assert_eq!(latest, "r-new", "older timestamp should not overwrite latest");
}

#[test]
fn subject_index_audit_slot_works() {
    use crate::subject_index_v1::{
        resolve_subject_receipt_id_v1, update_subject_index_v1, SubjectResolveModeV1,
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();

    update_subject_index_v1(root, "t1", "action", "a1", "r-10", "audit", "2026-03-01T00:00:00Z")
        .expect("create");

    let audit = resolve_subject_receipt_id_v1(root, "t1", "action", "a1", SubjectResolveModeV1::Audit)
        .expect("resolve")
        .expect("should exist");
    assert_eq!(audit, "r-10");

    // Verified should be None since we only wrote audit.
    let verified = resolve_subject_receipt_id_v1(root, "t1", "action", "a1", SubjectResolveModeV1::Verified)
        .expect("resolve");
    assert!(verified.is_none());
}

#[test]
fn resolve_nonexistent_subject_returns_none() {
    use crate::subject_index_v1::{resolve_subject_receipt_id_v1, SubjectResolveModeV1};

    let tmp = tempfile::tempdir().expect("tempdir");
    let result = resolve_subject_receipt_id_v1(
        tmp.path(),
        "t-missing",
        "answer",
        "s-missing",
        SubjectResolveModeV1::Latest,
    )
    .expect("resolve should not fail");
    assert!(result.is_none());
}

// ---------------------------------------------------------------------------
// body_v1 tests
// ---------------------------------------------------------------------------

#[test]
fn extract_body_index_all_fields() {
    use ciborium::value::Value;

    let body = Value::Map(vec![
        (Value::Text("kind".to_string()), Value::Text("answer".to_string())),
        (Value::Text("mode".to_string()), Value::Text("verified".to_string())),
        (
            Value::Text("subject".to_string()),
            Value::Map(vec![
                (Value::Text("type".to_string()), Value::Text("answer_id".to_string())),
                (Value::Text("id".to_string()), Value::Text("ans-42".to_string())),
            ]),
        ),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&body, &mut bytes).expect("encode");

    let idx = crate::extract_body_index_v1(&bytes).expect("should parse");
    assert_eq!(idx.kind.as_deref(), Some("answer"));
    assert_eq!(idx.mode.as_deref(), Some("verified"));
    assert_eq!(idx.subject_type.as_deref(), Some("answer_id"));
    assert_eq!(idx.subject_id.as_deref(), Some("ans-42"));
}

#[test]
fn extract_body_index_missing_fields() {
    use ciborium::value::Value;

    let body = Value::Map(vec![(
        Value::Text("schema".to_string()),
        Value::Text("cuecrux.receipt.body.v1".to_string()),
    )]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&body, &mut bytes).expect("encode");

    let idx = crate::extract_body_index_v1(&bytes).expect("should parse");
    assert!(idx.kind.is_none());
    assert!(idx.mode.is_none());
    assert!(idx.subject_type.is_none());
    assert!(idx.subject_id.is_none());
}

#[test]
fn extract_body_index_invalid_cbor_returns_none() {
    let result = crate::extract_body_index_v1(b"not-cbor");
    assert!(result.is_none());
}

#[test]
fn extract_body_index_non_map_returns_none() {
    use ciborium::value::Value;

    let body = Value::Array(vec![Value::Integer(1.into())]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&body, &mut bytes).expect("encode");

    let result = crate::extract_body_index_v1(&bytes);
    assert!(result.is_none());
}

#[test]
fn extract_linked_receipts_empty_body() {
    use ciborium::value::Value;

    let body = Value::Map(vec![(
        Value::Text("schema".to_string()),
        Value::Text("test".to_string()),
    )]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&body, &mut bytes).expect("encode");

    let out = crate::extract_linked_receipts_v1(&bytes).expect("parse");
    assert!(out.is_empty(), "no linked_receipts should return empty vec");
}

#[test]
fn extract_linked_receipts_invalid_cbor_returns_none() {
    let result = crate::extract_linked_receipts_v1(b"\xff\xff");
    assert!(result.is_none());
}

// ---------------------------------------------------------------------------
// keyring_v1 tests
// ---------------------------------------------------------------------------

#[test]
fn keyring_parse_json_valid() {
    use crate::keyring_v1::Ed25519KeyRingV1;

    let json = r#"{"v":1,"keys":[{"keyId":"k1","pubKeyBase64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}"#;
    let kr = Ed25519KeyRingV1::parse_json(json).expect("parse");
    assert_eq!(kr.v, 1);
    assert_eq!(kr.keys.len(), 1);
    assert_eq!(kr.keys[0].key_id, "k1");
}

#[test]
fn keyring_parse_json_rejects_version_2() {
    use crate::keyring_v1::Ed25519KeyRingV1;

    let json = r#"{"v":2,"keys":[{"keyId":"k1","pubKeyBase64":"AAAA"}]}"#;
    let err = Ed25519KeyRingV1::parse_json(json);
    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("unsupported keyring version"));
}

#[test]
fn keyring_parse_json_rejects_empty_keys() {
    use crate::keyring_v1::Ed25519KeyRingV1;

    let json = r#"{"v":1,"keys":[]}"#;
    let err = Ed25519KeyRingV1::parse_json(json);
    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("no keys"));
}

#[test]
fn keyring_parse_json_rejects_empty_key_id() {
    use crate::keyring_v1::Ed25519KeyRingV1;

    let json = r#"{"v":1,"keys":[{"keyId":"  ","pubKeyBase64":"AAAA"}]}"#;
    let err = Ed25519KeyRingV1::parse_json(json);
    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("empty keyId"));
}

#[test]
fn keyring_to_index_map_valid() {
    use crate::keyring_v1::{Ed25519KeyEntryV1, Ed25519KeyRingV1};

    let pk_bytes = [0u8; 32];
    let pk_b64 = base64::engine::general_purpose::STANDARD.encode(pk_bytes);

    let kr = Ed25519KeyRingV1 {
        v: 1,
        keys: vec![Ed25519KeyEntryV1 {
            key_id: "test-key".to_string(),
            pub_key_base64: pk_b64,
        }],
    };

    let map = kr.to_index_map().expect("to_index_map");
    assert_eq!(map.len(), 1);
    assert_eq!(map["test-key"], [0u8; 32]);
}

#[test]
fn keyring_to_index_map_wrong_length() {
    use crate::keyring_v1::{Ed25519KeyEntryV1, Ed25519KeyRingV1};

    let kr = Ed25519KeyRingV1 {
        v: 1,
        keys: vec![Ed25519KeyEntryV1 {
            key_id: "bad".to_string(),
            pub_key_base64: base64::engine::general_purpose::STANDARD.encode([0u8; 16]),
        }],
    };

    let err = kr.to_index_map();
    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("expected 32 bytes"));
}

#[test]
fn keyring_to_index_map_invalid_base64() {
    use crate::keyring_v1::{Ed25519KeyEntryV1, Ed25519KeyRingV1};

    let kr = Ed25519KeyRingV1 {
        v: 1,
        keys: vec![Ed25519KeyEntryV1 {
            key_id: "bad-b64".to_string(),
            pub_key_base64: "not-valid-base64!!!".to_string(),
        }],
    };

    let err = kr.to_index_map();
    assert!(err.is_err());
}

#[test]
fn keyring_multiple_keys_index_map() {
    use crate::keyring_v1::{Ed25519KeyEntryV1, Ed25519KeyRingV1};

    let pk1 = [1u8; 32];
    let pk2 = [2u8; 32];

    let kr = Ed25519KeyRingV1 {
        v: 1,
        keys: vec![
            Ed25519KeyEntryV1 {
                key_id: "k1".to_string(),
                pub_key_base64: base64::engine::general_purpose::STANDARD.encode(pk1),
            },
            Ed25519KeyEntryV1 {
                key_id: "k2".to_string(),
                pub_key_base64: base64::engine::general_purpose::STANDARD.encode(pk2),
            },
        ],
    };

    let map = kr.to_index_map().expect("to_index_map");
    assert_eq!(map.len(), 2);
    assert_eq!(map["k1"], pk1);
    assert_eq!(map["k2"], pk2);
}

// ---------------------------------------------------------------------------
// export_v1 tests
// ---------------------------------------------------------------------------

#[test]
fn export_format_parse_roundtrip() {
    use crate::export_v1::ExportFormatV1;

    assert_eq!(ExportFormatV1::parse("zip"), Some(ExportFormatV1::Zip));
    assert_eq!(ExportFormatV1::parse("tar.zst"), Some(ExportFormatV1::TarZst));
    assert_eq!(ExportFormatV1::parse("rar"), None);

    assert_eq!(ExportFormatV1::Zip.as_str(), "zip");
    assert_eq!(ExportFormatV1::TarZst.as_str(), "tar.zst");
}

#[test]
fn export_format_content_type_and_ext() {
    use crate::export_v1::ExportFormatV1;

    assert_eq!(ExportFormatV1::Zip.content_type(), "application/zip");
    assert_eq!(ExportFormatV1::Zip.filename_ext(), "zip");
    assert_eq!(ExportFormatV1::TarZst.content_type(), "application/zstd");
    assert_eq!(ExportFormatV1::TarZst.filename_ext(), "tar.zst");
}

#[test]
fn export_redaction_parse_roundtrip() {
    use crate::export_v1::ExportRedactionV1;

    assert_eq!(ExportRedactionV1::parse("none"), Some(ExportRedactionV1::None));
    assert_eq!(ExportRedactionV1::parse("metadata_only"), Some(ExportRedactionV1::MetadataOnly));
    assert_eq!(ExportRedactionV1::parse("tenant_safe"), Some(ExportRedactionV1::TenantSafe));
    assert_eq!(ExportRedactionV1::parse("full"), None);

    assert_eq!(ExportRedactionV1::None.as_str(), "none");
    assert_eq!(ExportRedactionV1::MetadataOnly.as_str(), "metadata_only");
    assert_eq!(ExportRedactionV1::TenantSafe.as_str(), "tenant_safe");
}

#[test]
fn export_include_parse_roundtrip() {
    use crate::export_v1::ReceiptExportIncludeV1;

    let cases = [
        ("body", ReceiptExportIncludeV1::Body),
        ("sig", ReceiptExportIncludeV1::Sig),
        ("verification", ReceiptExportIncludeV1::Verification),
        ("trace_summary", ReceiptExportIncludeV1::TraceSummary),
        ("subject_links", ReceiptExportIncludeV1::SubjectLinks),
        ("linked_receipts", ReceiptExportIncludeV1::LinkedReceipts),
    ];

    for (s, expected) in cases {
        assert_eq!(ReceiptExportIncludeV1::parse(s), Some(expected));
        assert_eq!(expected.as_str(), s);
    }
    assert_eq!(ReceiptExportIncludeV1::parse("foo"), None);
}

#[test]
fn export_options_default_is_zip_tenant_safe() {
    use crate::export_v1::{ExportFormatV1, ExportRedactionV1, ReceiptExportOptionsV1};

    let opts = ReceiptExportOptionsV1::default();
    assert_eq!(opts.format, ExportFormatV1::Zip);
    assert_eq!(opts.redaction, ExportRedactionV1::TenantSafe);
    assert!(opts.include.is_empty());
}

#[test]
fn export_tar_zst_format_works() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(555);
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    let sk = SigningKey::from_bytes(&sk_bytes);
    let vk = sk.verifying_key();

    let keyring = Ed25519KeyRingV1 {
        v: 1,
        keys: vec![Ed25519KeyEntryV1 {
            key_id: "k1".to_string(),
            pub_key_base64: base64::engine::general_purpose::STANDARD.encode(vk.as_bytes()),
        }],
    };

    let body = encode_body_cbor();
    let stored_hash = *blake3::hash(&body).as_bytes();
    let sig64 = sk.sign(&body).to_bytes().to_vec();

    let sig = ReceiptSigV1 {
        schema: "cuecrux.receipt.sig.v1".to_string(),
        receipt_id: "r-tar".to_string(),
        alg: "ed25519".to_string(),
        key_id: "k1".to_string(),
        signed_at: "2026-02-09T00:00:00Z".to_string(),
        signature: sig64,
        signed_payload_hash: stored_hash.to_vec(),
    };
    let sig_bytes = encode_sig_cbor(&sig);

    let build = corecrux_types::BuildInfo {
        version: "0.0.1".to_string(),
        commit: "deadbeef".to_string(),
    };

    let report = verify_receipt_v1(VerifyReceiptInput {
        tenant_id: "t1",
        receipt_id: "r-tar",
        body_bytes: &body,
        stored_body_payload_hash: stored_hash,
        sig_bytes: Some(&sig_bytes),
        keyring: Some(&keyring),
        verified_at: "2026-02-09T00:00:01Z",
        verifier_build: &build,
        recompute_candidate_digest: false,
    })
    .expect("verify");

    let bundle = build_receipt_export_v1(
        BuildReceiptExportInput {
            generated_at: "2026-02-09T00:00:01Z",
            tenant_id: "t1",
            receipt_id: "r-tar",
            build: &build,
            body_bytes: &body,
            sig_bytes: &sig_bytes,
            verification_report: &report,
            body_payload_hash_hex: &report.payload_hash_hex,
            sig_event_ref: "seq=1",
            event_headers: vec![],
            trace_summary_json: None,
            subject_links_json: None,
            lineage_json: None,
        },
        &ReceiptExportOptionsV1 {
            format: ExportFormatV1::TarZst,
            redaction: ExportRedactionV1::None,
            include: Vec::new(),
        },
    )
    .expect("export");

    assert_eq!(bundle.content_type, "application/zstd");
    assert_eq!(bundle.filename_ext, "tar.zst");
    assert!(!bundle.archive_bytes.is_empty());

    // Decompress and verify tar contents.
    let decompressed = zstd::decode_all(std::io::Cursor::new(&bundle.archive_bytes))
        .expect("zstd decode");
    let mut archive = tar::Archive::new(std::io::Cursor::new(&decompressed));
    let file_names: Vec<String> = archive
        .entries()
        .expect("entries")
        .filter_map(|e| {
            e.ok()
                .and_then(|entry| entry.path().ok().map(|p| p.to_string_lossy().to_string()))
        })
        .collect();
    assert!(file_names.contains(&"manifest.json".to_string()));
    assert!(file_names.contains(&"receipt/body.cbor".to_string()));
    assert!(file_names.contains(&"receipt/sig.cbor".to_string()));
    assert!(file_names.contains(&"verification/report.json".to_string()));
}

#[test]
fn export_tar_zst_is_deterministic() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(777);
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    let sk = SigningKey::from_bytes(&sk_bytes);
    let vk = sk.verifying_key();

    let keyring = Ed25519KeyRingV1 {
        v: 1,
        keys: vec![Ed25519KeyEntryV1 {
            key_id: "k1".to_string(),
            pub_key_base64: base64::engine::general_purpose::STANDARD.encode(vk.as_bytes()),
        }],
    };

    let body = encode_body_cbor();
    let stored_hash = *blake3::hash(&body).as_bytes();
    let sig64 = sk.sign(&body).to_bytes().to_vec();

    let sig = ReceiptSigV1 {
        schema: "cuecrux.receipt.sig.v1".to_string(),
        receipt_id: "r-det".to_string(),
        alg: "ed25519".to_string(),
        key_id: "k1".to_string(),
        signed_at: "2026-02-09T00:00:00Z".to_string(),
        signature: sig64,
        signed_payload_hash: stored_hash.to_vec(),
    };
    let sig_bytes = encode_sig_cbor(&sig);

    let build = corecrux_types::BuildInfo {
        version: "0.0.1".to_string(),
        commit: "deadbeef".to_string(),
    };

    let report = verify_receipt_v1(VerifyReceiptInput {
        tenant_id: "t1",
        receipt_id: "r-det",
        body_bytes: &body,
        stored_body_payload_hash: stored_hash,
        sig_bytes: Some(&sig_bytes),
        keyring: Some(&keyring),
        verified_at: "2026-02-09T00:00:01Z",
        verifier_build: &build,
        recompute_candidate_digest: false,
    })
    .expect("verify");

    let make_bundle = || {
        build_receipt_export_v1(
            BuildReceiptExportInput {
                generated_at: "2026-02-09T00:00:01Z",
                tenant_id: "t1",
                receipt_id: "r-det",
                build: &build,
                body_bytes: &body,
                sig_bytes: &sig_bytes,
                verification_report: &report,
                body_payload_hash_hex: &report.payload_hash_hex,
                sig_event_ref: "seq=1",
                event_headers: vec![],
                trace_summary_json: None,
                subject_links_json: None,
                lineage_json: None,
            },
            &ReceiptExportOptionsV1 {
                format: ExportFormatV1::TarZst,
                redaction: ExportRedactionV1::TenantSafe,
                include: Vec::new(),
            },
        )
        .expect("export")
    };

    let b1 = make_bundle();
    let b2 = make_bundle();
    assert_eq!(b1.archive_bytes, b2.archive_bytes, "tar.zst must be deterministic");
}

#[test]
fn export_trace_summary_precondition_error() {
    use crate::export_v1::{ExportFormatV1, ExportRedactionV1, ReceiptExportIncludeV1, ReceiptExportOptionsV1};

    let mut rng = rand::rngs::StdRng::seed_from_u64(999);
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    let sk = SigningKey::from_bytes(&sk_bytes);
    let vk = sk.verifying_key();

    let keyring = Ed25519KeyRingV1 {
        v: 1,
        keys: vec![Ed25519KeyEntryV1 {
            key_id: "k1".to_string(),
            pub_key_base64: base64::engine::general_purpose::STANDARD.encode(vk.as_bytes()),
        }],
    };

    let body = encode_body_cbor();
    let stored_hash = *blake3::hash(&body).as_bytes();
    let sig64 = sk.sign(&body).to_bytes().to_vec();
    let sig = ReceiptSigV1 {
        schema: "cuecrux.receipt.sig.v1".to_string(),
        receipt_id: "r-prec".to_string(),
        alg: "ed25519".to_string(),
        key_id: "k1".to_string(),
        signed_at: "2026-02-09T00:00:00Z".to_string(),
        signature: sig64,
        signed_payload_hash: stored_hash.to_vec(),
    };
    let sig_bytes = encode_sig_cbor(&sig);

    let build = corecrux_types::BuildInfo {
        version: "0.0.1".to_string(),
        commit: "deadbeef".to_string(),
    };

    let report = verify_receipt_v1(VerifyReceiptInput {
        tenant_id: "t1",
        receipt_id: "r-prec",
        body_bytes: &body,
        stored_body_payload_hash: stored_hash,
        sig_bytes: Some(&sig_bytes),
        keyring: Some(&keyring),
        verified_at: "2026-02-09T00:00:01Z",
        verifier_build: &build,
        recompute_candidate_digest: false,
    })
    .expect("verify");

    // Request trace_summary but don't provide it — should fail.
    let err = build_receipt_export_v1(
        BuildReceiptExportInput {
            generated_at: "2026-02-09T00:00:01Z",
            tenant_id: "t1",
            receipt_id: "r-prec",
            build: &build,
            body_bytes: &body,
            sig_bytes: &sig_bytes,
            verification_report: &report,
            body_payload_hash_hex: &report.payload_hash_hex,
            sig_event_ref: "seq=1",
            event_headers: vec![],
            trace_summary_json: None,
            subject_links_json: None,
            lineage_json: None,
        },
        &ReceiptExportOptionsV1 {
            format: ExportFormatV1::Zip,
            redaction: ExportRedactionV1::None,
            include: vec![ReceiptExportIncludeV1::TraceSummary],
        },
    );

    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("trace_summary"));
}

// ---------------------------------------------------------------------------
// verify_v1 additional edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn verify_no_sig_no_keyring_returns_sig_missing() {
    let body = encode_body_cbor();
    let stored_hash = *blake3::hash(&body).as_bytes();

    let build = corecrux_types::BuildInfo {
        version: "0.0.1".to_string(),
        commit: "deadbeef".to_string(),
    };

    let report = verify_receipt_v1(VerifyReceiptInput {
        tenant_id: "t1",
        receipt_id: "r-nosig",
        body_bytes: &body,
        stored_body_payload_hash: stored_hash,
        sig_bytes: None,
        keyring: None,
        verified_at: "2026-02-09T00:00:01Z",
        verifier_build: &build,
        recompute_candidate_digest: false,
    })
    .expect("verify");

    assert_eq!(report.error_code, "SIG_MISSING");
    assert!(!report.signature_valid);
    assert!(report.integrity.payload_hash_matches);
    assert!(report.integrity.canonical_bytes_parse_ok);
}

#[test]
fn verify_error_code_as_str_all_variants() {
    use crate::verify_v1::VerifyErrorCodeV1;

    let cases = [
        (VerifyErrorCodeV1::Ok, "OK"),
        (VerifyErrorCodeV1::BodyHashMismatch, "BODY_HASH_MISMATCH"),
        (VerifyErrorCodeV1::BodyCborParseError, "BODY_CBOR_PARSE_ERROR"),
        (VerifyErrorCodeV1::SigMissing, "SIG_MISSING"),
        (VerifyErrorCodeV1::SigParseError, "SIG_PARSE_ERROR"),
        (VerifyErrorCodeV1::SigAlgUnsupported, "SIG_ALG_UNSUPPORTED"),
        (VerifyErrorCodeV1::SigReceiptIdMismatch, "SIG_RECEIPT_ID_MISMATCH"),
        (VerifyErrorCodeV1::SigPayloadHashMismatch, "SIG_PAYLOAD_HASH_MISMATCH"),
        (VerifyErrorCodeV1::KeyRingMissing, "KEYRING_MISSING"),
        (VerifyErrorCodeV1::KeyNotFound, "KEY_NOT_FOUND"),
        (VerifyErrorCodeV1::PubKeyInvalid, "PUBKEY_INVALID"),
        (VerifyErrorCodeV1::SigInvalid, "SIG_INVALID"),
    ];

    for (code, expected) in cases {
        assert_eq!(code.as_str(), expected);
    }
}

#[test]
fn verify_with_unparseable_sig_cbor() {
    let body = encode_body_cbor();
    let stored_hash = *blake3::hash(&body).as_bytes();

    let build = corecrux_types::BuildInfo {
        version: "0.0.1".to_string(),
        commit: "deadbeef".to_string(),
    };

    let bogus_sig = b"this-is-not-cbor";

    let report = verify_receipt_v1(VerifyReceiptInput {
        tenant_id: "t1",
        receipt_id: "r-badsig",
        body_bytes: &body,
        stored_body_payload_hash: stored_hash,
        sig_bytes: Some(bogus_sig),
        keyring: None,
        verified_at: "2026-02-09T00:00:01Z",
        verifier_build: &build,
        recompute_candidate_digest: false,
    })
    .expect("verify should not hard-error");

    assert_eq!(report.error_code, "SIG_PARSE_ERROR");
    assert!(!report.signature_valid);
}

#[test]
fn verify_receipt_id_mismatch_in_sig() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    let sk = SigningKey::from_bytes(&sk_bytes);
    let vk = sk.verifying_key();

    let keyring = Ed25519KeyRingV1 {
        v: 1,
        keys: vec![Ed25519KeyEntryV1 {
            key_id: "k1".to_string(),
            pub_key_base64: base64::engine::general_purpose::STANDARD.encode(vk.as_bytes()),
        }],
    };

    let body = encode_body_cbor();
    let stored_hash = *blake3::hash(&body).as_bytes();

    let sig = ReceiptSigV1 {
        schema: "cuecrux.receipt.sig.v1".to_string(),
        receipt_id: "wrong-receipt-id".to_string(),
        alg: "ed25519".to_string(),
        key_id: "k1".to_string(),
        signed_at: "2026-02-09T00:00:00Z".to_string(),
        signature: sk.sign(&body).to_bytes().to_vec(),
        signed_payload_hash: stored_hash.to_vec(),
    };
    let sig_bytes = encode_sig_cbor(&sig);

    let build = corecrux_types::BuildInfo {
        version: "0.0.1".to_string(),
        commit: "deadbeef".to_string(),
    };

    let report = verify_receipt_v1(VerifyReceiptInput {
        tenant_id: "t1",
        receipt_id: "correct-receipt-id",
        body_bytes: &body,
        stored_body_payload_hash: stored_hash,
        sig_bytes: Some(&sig_bytes),
        keyring: Some(&keyring),
        verified_at: "2026-02-09T00:00:01Z",
        verifier_build: &build,
        recompute_candidate_digest: false,
    })
    .expect("verify");

    assert_eq!(report.error_code, "SIG_RECEIPT_ID_MISMATCH");
    assert!(!report.signature_valid);
}

#[test]
fn verify_unsupported_alg() {
    let body = encode_body_cbor();
    let stored_hash = *blake3::hash(&body).as_bytes();

    let sig = ReceiptSigV1 {
        schema: "cuecrux.receipt.sig.v1".to_string(),
        receipt_id: "r-alg".to_string(),
        alg: "rsa-sha256".to_string(),
        key_id: "k1".to_string(),
        signed_at: "2026-02-09T00:00:00Z".to_string(),
        signature: vec![0u8; 64],
        signed_payload_hash: stored_hash.to_vec(),
    };
    let sig_bytes = encode_sig_cbor(&sig);

    let keyring = Ed25519KeyRingV1 {
        v: 1,
        keys: vec![Ed25519KeyEntryV1 {
            key_id: "k1".to_string(),
            pub_key_base64: base64::engine::general_purpose::STANDARD.encode([0u8; 32]),
        }],
    };

    let build = corecrux_types::BuildInfo {
        version: "0.0.1".to_string(),
        commit: "deadbeef".to_string(),
    };

    let report = verify_receipt_v1(VerifyReceiptInput {
        tenant_id: "t1",
        receipt_id: "r-alg",
        body_bytes: &body,
        stored_body_payload_hash: stored_hash,
        sig_bytes: Some(&sig_bytes),
        keyring: Some(&keyring),
        verified_at: "2026-02-09T00:00:01Z",
        verifier_build: &build,
        recompute_candidate_digest: false,
    })
    .expect("verify");

    assert_eq!(report.error_code, "SIG_ALG_UNSUPPORTED");
}

#[test]
fn verify_sig_payload_hash_mismatch() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(88);
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    let sk = SigningKey::from_bytes(&sk_bytes);
    let vk = sk.verifying_key();

    let keyring = Ed25519KeyRingV1 {
        v: 1,
        keys: vec![Ed25519KeyEntryV1 {
            key_id: "k1".to_string(),
            pub_key_base64: base64::engine::general_purpose::STANDARD.encode(vk.as_bytes()),
        }],
    };

    let body = encode_body_cbor();
    let stored_hash = *blake3::hash(&body).as_bytes();

    let sig = ReceiptSigV1 {
        schema: "cuecrux.receipt.sig.v1".to_string(),
        receipt_id: "r-phm".to_string(),
        alg: "ed25519".to_string(),
        key_id: "k1".to_string(),
        signed_at: "2026-02-09T00:00:00Z".to_string(),
        signature: sk.sign(&body).to_bytes().to_vec(),
        signed_payload_hash: vec![0u8; 32], // wrong hash
    };
    let sig_bytes = encode_sig_cbor(&sig);

    let build = corecrux_types::BuildInfo {
        version: "0.0.1".to_string(),
        commit: "deadbeef".to_string(),
    };

    let report = verify_receipt_v1(VerifyReceiptInput {
        tenant_id: "t1",
        receipt_id: "r-phm",
        body_bytes: &body,
        stored_body_payload_hash: stored_hash,
        sig_bytes: Some(&sig_bytes),
        keyring: Some(&keyring),
        verified_at: "2026-02-09T00:00:01Z",
        verifier_build: &build,
        recompute_candidate_digest: false,
    })
    .expect("verify");

    assert_eq!(report.error_code, "SIG_PAYLOAD_HASH_MISMATCH");
}

#[test]
fn verify_keyring_missing_returns_keyring_missing() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(66);
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    let sk = SigningKey::from_bytes(&sk_bytes);

    let body = encode_body_cbor();
    let stored_hash = *blake3::hash(&body).as_bytes();

    let sig = ReceiptSigV1 {
        schema: "cuecrux.receipt.sig.v1".to_string(),
        receipt_id: "r-kr".to_string(),
        alg: "ed25519".to_string(),
        key_id: "k1".to_string(),
        signed_at: "2026-02-09T00:00:00Z".to_string(),
        signature: sk.sign(&body).to_bytes().to_vec(),
        signed_payload_hash: stored_hash.to_vec(),
    };
    let sig_bytes = encode_sig_cbor(&sig);

    let build = corecrux_types::BuildInfo {
        version: "0.0.1".to_string(),
        commit: "deadbeef".to_string(),
    };

    let report = verify_receipt_v1(VerifyReceiptInput {
        tenant_id: "t1",
        receipt_id: "r-kr",
        body_bytes: &body,
        stored_body_payload_hash: stored_hash,
        sig_bytes: Some(&sig_bytes),
        keyring: None, // no keyring
        verified_at: "2026-02-09T00:00:01Z",
        verifier_build: &build,
        recompute_candidate_digest: false,
    })
    .expect("verify");

    assert_eq!(report.error_code, "KEYRING_MISSING");
}

// ---------------------------------------------------------------------------
// Constant smoke tests
// ---------------------------------------------------------------------------

#[test]
fn constants_are_stable() {
    assert_eq!(crate::STREAM_TYPE_RECEIPT, "receipt");
    assert_eq!(crate::EVT_RECEIPT_BODY_V1, "receipt.body.v1");
    assert_eq!(crate::EVT_RECEIPT_SIG_V1, "receipt.sig.v1");
    assert_eq!(
        crate::CONTENT_TYPE_RECEIPT_BODY_V1,
        "application/cbor; profile=cuecrux-receipt-body-v1"
    );
    assert_eq!(
        crate::CONTENT_TYPE_RECEIPT_SIG_V1,
        "application/cbor; profile=cuecrux-receipt-sig-v1"
    );
}
