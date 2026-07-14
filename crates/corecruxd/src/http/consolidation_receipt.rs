// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Signed, offline-verifiable consolidation receipts (ExecPlan
//! `crux-daemon-buyer-fit-buildout-2026-07-13`, M2.2 — "Dreams with receipts").
//!
//! Wires the existing (previously un-called) CROWN signer
//! `corecrux_receipts::sign_consolidation_v1` into the consolidation op. Each
//! consolidation (and each undo) emits a signed receipt binding
//! `{consolidation_id, canonical_fact_id, canonical_hash (after), superseded
//! source ids (before), strategy, actor}`. The signature is Ed25519 over the
//! deterministic CBOR body, so a third party can verify the diff offline with
//! only the daemon's public key — no daemon required.

use corecrux_memory::fact_store::ConsolidationReceiptV1;
use corecrux_receipts::{build_consolidation_body_v1, sign_consolidation_v1, ConsolidationBodyInputV1};
use ed25519_dalek::SigningKey;

use super::AppState;

/// Load the daemon passport signing key (best-effort). Mirrors
/// `stream_receipts::load_signing_key`; returns `None` when no passport key is
/// configured (receipts are then omitted rather than failing the mutation).
fn signing_key(state: &AppState) -> Option<SigningKey> {
    let content = std::fs::read_to_string(&state.passport_key_path).ok()?;
    let decoded = hex::decode(content.trim()).ok()?;
    let seed: [u8; 32] = decoded.as_slice().try_into().ok()?;
    let key = crux_session::LocalPassportKey::from_seed(seed).ok()?;
    if key.passport_fpr() != state.passport_fpr {
        return None;
    }
    Some(SigningKey::from_bytes(&seed))
}

/// Mint a signed, offline-verifiable receipt for a consolidation or its undo
/// (`strategy = "canonical_merge"` / `"undo"`). Best-effort: `None` if no
/// passport key is available (the mutation already succeeded; the receipt is an
/// audit record over it).
pub(super) fn mint_consolidation_receipt(
    state: &AppState,
    receipt: &ConsolidationReceiptV1,
    entity: &str,
    key: &str,
    actor: &str,
    strategy: &str,
    created_at: &str,
) -> Option<serde_json::Value> {
    let signing_key = signing_key(state)?;
    let receipt_id = format!("rcon_{}", uuid::Uuid::new_v4());
    let superseded: Vec<&str> = receipt.superseded_fact_ids.iter().map(String::as_str).collect();
    let (body_bytes, body_hash) = build_consolidation_body_v1(&ConsolidationBodyInputV1 {
        tenant_id: "local",
        receipt_id: &receipt_id,
        consolidation_id: &receipt.consolidation_id,
        actor_passport: actor,
        target_entity: entity,
        target_key: Some(key),
        canonical_fact_id: &receipt.canonical_fact_id,
        canonical_hash: &receipt.canonical_hash,
        strategy,
        superseded_fact_ids: &superseded,
        source_receipts: &[],
        created_at,
    });
    let sig = sign_consolidation_v1(
        &receipt_id,
        &body_bytes,
        body_hash,
        &signing_key,
        &state.passport_fpr,
        created_at,
    );
    Some(serde_json::json!({
        "schema": "crux.consolidation_receipt.v1",
        "kind": "consolidation",
        "strategy": strategy,
        "receipt_id": receipt_id,
        // The signed CBOR body + its hash: everything a verifier needs offline.
        "body_cbor_hex": hex::encode(&body_bytes),
        "body_hash": hex::encode(body_hash),
        "signer_fpr": state.passport_fpr,
        "signer_public_key_hex": state.passport_public_key_hex,
        "sig": sig,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    #[test]
    fn consolidation_receipt_verifies_offline_and_tamper_fails() {
        // Deterministic test signing key.
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let receipt_id = "rcon_test";
        let superseded = ["f_a", "f_b"];
        let (body, hash) = build_consolidation_body_v1(&ConsolidationBodyInputV1 {
            tenant_id: "local",
            receipt_id,
            consolidation_id: "con-1",
            actor_passport: "agent:codex",
            target_entity: "proj",
            target_key: Some("status"),
            canonical_fact_id: "f_canon",
            canonical_hash: "blake3:deadbeef",
            strategy: "canonical_merge",
            superseded_fact_ids: &superseded,
            source_receipts: &[],
            created_at: "2026-07-14T00:00:00Z",
        });
        let sig = sign_consolidation_v1(receipt_id, &body, hash, &sk, "fpr:test", "2026-07-14T00:00:00Z");

        // Offline verify: signature is Ed25519 over the canonical body bytes.
        let signature = Signature::from_slice(&sig.signature).expect("sig bytes");
        assert!(vk.verify(&body, &signature).is_ok(), "valid receipt verifies offline");
        assert!(
            corecrux_receipts::assert_consolidation_kind_v1(&body),
            "body is a consolidation-kind receipt"
        );

        // Tamper: a single flipped body byte must fail verification.
        let mut tampered = body.clone();
        tampered[0] ^= 0x01;
        assert!(
            vk.verify(&tampered, &signature).is_err(),
            "tampered body fails offline verify"
        );
    }
}
