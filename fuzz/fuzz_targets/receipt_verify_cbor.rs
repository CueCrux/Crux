#![no_main]

use corecrux_receipts::{verify_receipt_v1, VerifyReceiptInput};
use corecrux_types::BuildInfo;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let split_at = data.len() / 2;
    let (body_bytes, sig_bytes) = data.split_at(split_at);
    let stored_body_payload_hash = *blake3::hash(body_bytes).as_bytes();
    let verifier_build = BuildInfo {
        version: "fuzz".to_string(),
        commit: "fuzz".to_string(),
    };

    let _ = verify_receipt_v1(VerifyReceiptInput {
        tenant_id: "fuzz-tenant",
        receipt_id: "fuzz-receipt",
        body_bytes,
        stored_body_payload_hash,
        sig_bytes: Some(sig_bytes),
        keyring: None,
        verified_at: "1970-01-01T00:00:00Z",
        verifier_build: &verifier_build,
        recompute_candidate_digest: true,
    });
});
