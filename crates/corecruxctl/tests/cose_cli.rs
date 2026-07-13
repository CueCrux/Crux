// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_corecruxctl"))
        .args(args)
        .output()
        .expect("run corecruxctl receipts COSE command")
}

#[test]
fn export_with_dev_key_then_verify_cose() {
    let temp = tempfile::tempdir().unwrap();
    let receipt_path = temp.path().join("receipt.json");
    let cose_path = temp.path().join("receipt.cose");
    std::fs::write(
        &receipt_path,
        br#"{
  "snapshotId": "d0000001-0001-4000-8000-000000000001",
  "answerId": "c0000001-0001-4000-8000-000000000001",
  "parentSnapId": null,
  "generatedAt": "2026-03-24T12:00:01Z",
  "mode": "verified",
  "modeRequested": "verified",
  "queryHash": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "queryText": "What evidence supports this answer?",
  "receiptHash": "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "tenantId": "tenant-test",
  "fusion": { "w_bm25": 0.5, "w_vec": 0.5, "rrf_k": 60 },
  "retrieval": { "topK": 10, "rerank": true, "minDomains": 1, "budget": "balanced" },
  "selection": {
    "miSESSize": 1,
    "citationIds": ["doc-1"],
    "distinctDomains": 1
  },
  "timings": { "retrieveMs": 12, "rerankMs": 3, "llmMs": 40, "totalMs": 55 }
}"#,
    )
    .unwrap();

    let export = run(&[
        "receipts",
        "export-cose",
        receipt_path.to_str().unwrap(),
        "--out",
        cose_path.to_str().unwrap(),
        "--gen-dev-key",
        "--kid",
        "crux-cose-cli-test-v1",
    ]);
    assert!(
        export.status.success(),
        "export failed: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    assert!(cose_path.is_file());
    let export_stdout = String::from_utf8_lossy(&export.stdout);
    assert!(export_stdout.contains("COSE_Sign1 exported:"));
    assert!(export_stdout.contains("snap-id=d0000001-0001-4000-8000-000000000001"));

    let verify = run(&["receipts", "verify-cose", cose_path.to_str().unwrap()]);
    assert!(
        verify.status.success(),
        "verification failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let verify_stdout = String::from_utf8_lossy(&verify.stdout);
    assert!(verify_stdout.contains("COSE_Sign1 verification OK:"));
    assert!(verify_stdout.contains("kid=crux-cose-cli-test-v1"));
}
