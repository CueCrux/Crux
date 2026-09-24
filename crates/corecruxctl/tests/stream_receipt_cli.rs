// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `corecruxctl receipts verify-stream-receipt`: exit status and the signed
//! fields it prints.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use base64::Engine as _;
use corecrux_receipts::ReceiptSigV1;
use ed25519_dalek::SigningKey;

const KEY_ID: &str = "fpr-daemon";

fn daemon_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// One `/v1/observations/aggregate` record as the daemon persists it: the
/// signed body plus UNSIGNED top-level copies (`kind`, `output_hash`, ...).
fn write_record(dir: &Path, name: &str, receipt_id: &str, body: &[u8], hash: [u8; 32], sig: &ReceiptSigV1) -> PathBuf {
    let path = dir.join(name);
    let record = serde_json::json!({
        "observation_id": "obs-1",
        "kind": "model_invocation",
        "payload": {
            "receipt_id": receipt_id,
            "kind": "model_invocation",
            "body_cbor_hex": hex::encode(body),
            "body_hash": format!("blake3:{}", hex::encode(hash)),
            "sig": {
                "schema": sig.schema,
                "alg": sig.alg,
                "key_id": sig.key_id,
                "signed_at": sig.signed_at,
                "signature_hex": hex::encode(&sig.signature),
            },
            // Unsigned copies, deliberately disagreeing with the signed body.
            "invocation_id": "inv-forged",
            "prompt_hash": "blake3:forged-prompt",
            "output_hash": "blake3:deny",
        },
    });
    std::fs::write(&path, record.to_string()).unwrap();
    path
}

fn model_invocation_record(dir: &Path) -> PathBuf {
    let (body, hash) =
        corecrux_receipts::build_model_invocation_body_v1(&corecrux_receipts::ModelInvocationBodyInputV1 {
            tenant_id: "local",
            receipt_id: "r_jev_1",
            invocation_id: "inv-1",
            actor_passport: "operator",
            provider: "typesafe",
            model_id: "jev",
            model_version: None,
            provider_request_id: None,
            prompt_hash: "blake3:prompt",
            retrieval_set_hash: None,
            output_hash: Some("blake3:allow"),
            temperature: None,
            top_p: None,
            seed: None,
            max_tokens: None,
            started_at: "2026-09-22T00:00:00Z",
            completed_at: None,
            created_at: "2026-09-22T00:00:00Z",
        });
    let sig = corecrux_receipts::sign_model_invocation_v1("r_jev_1", &body, hash, &daemon_key(), KEY_ID, "t");
    write_record(dir, "model_invocation.json", "r_jev_1", &body, hash, &sig)
}

fn usage_ping_record(dir: &Path) -> PathBuf {
    let (body, hash) = corecrux_receipts::build_usage_ping_body_v1(&corecrux_receipts::UsagePingBodyInputV1 {
        tenant_id: "local",
        receipt_id: "r_ping_1",
        passport_fpr: KEY_ID,
        event_class: corecrux_receipts::UsageEventClassV1::Session,
        count: 1,
        created_at: "2026-09-22T00:00:00Z",
    });
    let sig = corecrux_receipts::sign_usage_ping_v1("r_ping_1", &body, hash, &daemon_key(), KEY_ID, "t");
    write_record(dir, "usage_ping.json", "r_ping_1", &body, hash, &sig)
}

fn keyring(dir: &Path) -> PathBuf {
    let path = dir.join("keyring.json");
    let pub_key = base64::engine::general_purpose::STANDARD.encode(daemon_key().verifying_key().as_bytes());
    std::fs::write(
        &path,
        serde_json::json!({"v": 1, "keys": [{"keyId": KEY_ID, "pubKeyBase64": pub_key}]}).to_string(),
    )
    .unwrap();
    path
}

fn verify(record: &Path, keyring: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_corecruxctl"))
        .args(["receipts", "verify-stream-receipt"])
        .arg(record)
        .arg("--keyring")
        .arg(keyring)
        .args(extra)
        .output()
        .expect("run corecruxctl receipts verify-stream-receipt")
}

#[test]
fn prints_signed_body_fields_not_the_unsigned_payload_copies() {
    let dir = tempfile::tempdir().unwrap();
    let out = verify(
        &model_invocation_record(dir.path()),
        &keyring(dir.path()),
        &["--expect-receipt-id", "r_jev_1", "--kind", "model_invocation"],
    );
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let printed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        printed,
        serde_json::json!({
            "kind": "model_invocation",
            "receipt_id": "r_jev_1",
            "tenant_id": "local",
            "invocation_id": "inv-1",
            "provider": "typesafe",
            "model_id": "jev",
            "prompt_hash": "blake3:prompt",
            "output_hash": "blake3:allow",
        })
    );
}

#[test]
fn mismatched_expectations_and_non_stream_kinds_exit_non_zero() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = keyring(dir.path());
    let record = model_invocation_record(dir.path());
    for (record, extra) in [
        (&record, &["--expect-receipt-id", "r_other"][..]),
        (&record, &["--kind", "stream_completed"][..]),
        // Genuine daemon signature, same key and tenant, but not a stream receipt.
        (&usage_ping_record(dir.path()), &[][..]),
    ] {
        let out = verify(record, &keyring, extra);
        assert!(!out.status.success(), "{extra:?} passed");
        assert!(out.stdout.is_empty(), "{extra:?} printed fields on failure");
        assert!(String::from_utf8_lossy(&out.stderr).contains("NOT verified"));
    }
}
