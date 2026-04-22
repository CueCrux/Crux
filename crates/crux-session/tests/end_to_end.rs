// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! End-to-end integration test for the handshake pipeline.
//!
//! Mirrors the sequence that CE's `POST /session` and hosted's
//! `POST /v1/session` execute: synthesise (or accept) a passport, mint a
//! plan, insert into the registry, re-decode from canonical CBOR, and
//! verify the hash (+ signature, for verified mode).

use std::collections::HashSet;

use crux_session::{
    mint, plan_receipt_hash, verify_plan_signature, Budget, Channels, GraphHints, HandshakeInputs, HandshakeRequest,
    InMemoryRegistry, InProcessEd25519Signer, LocalPassportConfig, NullSigner, ReceiptMode, RegistryEntry, SessionPlan,
    SessionRegistry, DEFAULT_CATALOG,
};

fn ce_handshake(signer: &dyn crux_session::PlanSigner) -> (SessionPlan, Vec<u8>) {
    let cfg = LocalPassportConfig {
        install_uuid: "install-end-to-end".into(),
        user: "tester".into(),
    };
    let (passport, origin_install) = cfg.synthesise();

    let request = HandshakeRequest {
        passport,
        channels: Channels {
            bulk: Some("h2://localhost:14801/v2".into()),
            mcp: "http://localhost:14800/mcp".into(),
        },
        hints: GraphHints {
            prefer_bulk: true,
            intent: None,
            max_capabilities: None,
        },
        session_ttl_s: 1800,
        budget: Budget {
            tokens_cap: None,
            crux_cap: None,
            ttl_s: 1800,
        },
        origin: "ce".into(),
        origin_install: Some(origin_install),
        intent_hint: None,
        now_ms: 1_745_000_000_000,
    };

    let sealed = mint(
        request,
        HandshakeInputs {
            catalog: DEFAULT_CATALOG,
            enabled_feature_flags: &HashSet::new(),
            signer,
        },
    )
    .expect("mint");

    (sealed.plan, sealed.canonical_cbor)
}

#[test]
fn ce_handshake_full_flow() {
    let (plan, canonical_cbor) = ce_handshake(&NullSigner);

    // 1. Receipt mode + shape invariants.
    assert_eq!(plan.receipt.mode, ReceiptMode::Local);
    assert!(plan.receipt.signature.is_none());
    assert_ne!(plan.receipt.hash, [0u8; 32]);
    assert_eq!(plan.origin, "ce");
    assert!(plan.passport.principal_id.starts_with("ce:"));
    assert!(!plan.capability_graph.is_empty());

    // 2. Registry round-trip.
    let registry = InMemoryRegistry::new();
    let entry = RegistryEntry::from_plan(&plan, canonical_cbor.clone());
    registry.insert(entry).unwrap();
    let looked_up = registry.get(&plan.session_id).unwrap().expect("found");
    assert_eq!(looked_up.principal_id, plan.passport.principal_id);
    assert_eq!(looked_up.capability_graph_hash, plan.capability_graph_hash);
    assert_eq!(looked_up.plan_receipt_hash, plan.receipt.hash);

    // 3. CBOR round-trip: the bytes returned in the response re-decode to
    // an identical plan and the hash self-verifies.
    let decoded = SessionPlan::from_canonical_cbor(&canonical_cbor).expect("decode");
    assert_eq!(decoded.receipt.hash, plan.receipt.hash);
    let recomputed = plan_receipt_hash(&decoded);
    assert_eq!(recomputed, plan.receipt.hash);
}

#[test]
fn hosted_handshake_full_flow_with_signature() {
    let signer = InProcessEd25519Signer::from_seed([13u8; 32], "test-kid");
    let pk = signer.verifying_key_bytes();
    let (plan, canonical_cbor) = ce_handshake(&signer);

    assert_eq!(plan.receipt.mode, ReceiptMode::Verified);
    assert!(plan.receipt.signature.is_some());
    verify_plan_signature(&plan, &pk).expect("signature verify");

    // Tampering: flipping a capability's prefer field must invalidate the hash.
    let mut tampered = plan.clone();
    if let Some(first) = tampered.capability_graph.first_mut() {
        first.prefer = if first.prefer == "bulk" {
            "mcp".into()
        } else {
            "bulk".into()
        };
    }
    let recomputed = plan_receipt_hash(&tampered);
    assert_ne!(recomputed, plan.receipt.hash);

    // Decoded plan re-encodes byte-identically.
    let decoded = SessionPlan::from_canonical_cbor(&canonical_cbor).expect("decode");
    assert_eq!(decoded.to_canonical_cbor(), canonical_cbor);
}

#[test]
fn ce_capability_graph_is_local_scoped() {
    let (plan, _) = ce_handshake(&NullSigner);
    // CE passport has affinities = ["*"] — every catalog entry that passes
    // the tier filter should be visible. The `local` tier bars capabilities
    // requiring `free` or higher — confirm the graph is non-empty but does
    // not include pro/team-tier capabilities.
    let names: Vec<&str> = plan.capability_graph.iter().map(|c| c.cap.as_str()).collect();
    assert!(names.contains(&"session_context"));
    assert!(names.contains(&"journal_append"));
    // pro-tier capability should NOT be present because `local` < `pro`.
    assert!(!names.contains(&"audit_replay"));
    assert!(!names.contains(&"get_counterfactual_summary"));
}
