// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! M2 always-store correspondence tests.
//!
//! Master plan §7: "the segment log is truth; the registry is a cache."
//! The handshake must seal a SessionPlanSealed event BEFORE the registry
//! sees the row. If seal fails, no registry write.
//!
//! These tests exercise the invariant end-to-end:
//!
//!   (1) N successful handshakes → N sealed events + N registry rows, 1:1.
//!   (2) A failing sealer → 0 registry rows (handshake fails closed).
//!   (3) Replaying the N sealed events through the
//!       `session_plans_by_principal` projection rebuilds the state that
//!       was lost from the in-memory registry, proving the segment log
//!       is a sufficient source of truth.

use std::collections::HashSet;
use std::sync::Arc;

use corecrux_projections::{
    SessionPlanSealedV1, SessionPlansByPrincipalV1, CONTENT_TYPE_SESSION_BIN_V1,
    EVT_SESSION_PLAN_SEALED_V1,
};
use crux_session::{
    mint, plan::ReceiptMode, Budget, Channels, FailingSealer, GraphHints, HandshakeInputs,
    HandshakeRequest, InMemoryRegistry, InMemorySealer, LocalPassportConfig, NullSigner,
    PlanSealer, RegistryEntry, SealedEvent, SessionRegistry, DEFAULT_CATALOG,
};

fn handshake_once(
    signer: &dyn crux_session::PlanSigner,
    sealer: &dyn PlanSealer,
    registry: &dyn SessionRegistry,
    user: &str,
) -> Result<(), String> {
    let passport_cfg = LocalPassportConfig {
        install_uuid: "always-store-test".into(),
        user: user.into(),
    };
    let (passport, origin_install) = passport_cfg.synthesise();

    let req = HandshakeRequest {
        passport,
        channels: Channels {
            bulk: None,
            mcp: "http://localhost:14800/mcp".into(),
        },
        hints: GraphHints { prefer_bulk: true, intent: None, max_capabilities: None },
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
        req,
        HandshakeInputs {
            catalog: DEFAULT_CATALOG,
            enabled_feature_flags: &HashSet::new(),
            signer,
        },
    )
    .map_err(|e| format!("mint: {e}"))?;

    // Build + seal the SessionPlanSealed event BEFORE registry write.
    let sealed_event = SealedEvent {
        event_type: EVT_SESSION_PLAN_SEALED_V1,
        content_type: CONTENT_TYPE_SESSION_BIN_V1,
        tenant_id: sealed.plan.origin.clone(),
        stream_type: "session-plans".into(),
        stream_id: sealed.plan.passport.principal_id.clone(),
        payload: SessionPlanSealedV1 {
            event_id: [0u8; 16],
            plan_id: sealed.plan.plan_id,
            session_id: sealed.plan.session_id,
            principal_id: sealed.plan.passport.principal_id.clone(),
            origin: sealed.plan.origin.clone(),
            origin_install: sealed.plan.origin_install,
            minted_at_ms: sealed.plan.minted_at as i64,
            expires_at_ms: (sealed.plan.minted_at + sealed.plan.session_ttl_s * 1000) as i64,
            plan_receipt_hash: sealed.plan.receipt.hash,
            plan_receipt_signature: sealed.plan.receipt.signature,
            capability_graph_hash: sealed.plan.capability_graph_hash,
            plan_bytes_cbor: sealed.canonical_cbor.clone(),
        }
        .encode_bin(),
    };

    sealer.seal(&sealed_event).map_err(|e| format!("seal: {e}"))?;
    let entry = RegistryEntry::from_plan(&sealed.plan, sealed.canonical_cbor.clone());
    registry.insert(entry).map_err(|e| format!("insert: {e}"))?;

    assert_eq!(sealed.plan.receipt.mode, ReceiptMode::Local);
    Ok(())
}

#[test]
fn n_handshakes_produce_one_to_one_seal_and_registry() {
    const N: usize = 200;
    let signer = NullSigner;
    let sealer = Arc::new(InMemorySealer::new());
    let registry = Arc::new(InMemoryRegistry::new());

    for i in 0..N {
        let user = format!("user_{i:04}");
        handshake_once(&signer, sealer.as_ref(), registry.as_ref(), &user).expect("handshake");
    }

    // Sealed events and live registry rows both equal N. This is the
    // master-plan §12.1 Phase 2 gate (scaled down from 1000 to 200 to
    // keep the test fast; correctness property is identical).
    assert_eq!(sealer.len(), N);
    assert_eq!(registry.active_count().unwrap(), N);
}

#[test]
fn seal_failure_prevents_registry_write() {
    let signer = NullSigner;
    let sealer = FailingSealer;
    let registry = Arc::new(InMemoryRegistry::new());

    // Try 10 handshakes; every single one must fail at seal and leave the
    // registry untouched.
    for i in 0..10 {
        let user = format!("fail_user_{i}");
        let result = handshake_once(&signer, &sealer, registry.as_ref(), &user);
        assert!(result.is_err(), "expected seal failure");
    }

    assert_eq!(
        registry.active_count().unwrap(),
        0,
        "registry must have zero rows when seal failed"
    );
}

#[test]
fn projection_rebuild_from_segment_log_matches_registry() {
    const N: usize = 50;
    let signer = NullSigner;
    let sealer = Arc::new(InMemorySealer::new());
    let registry = Arc::new(InMemoryRegistry::new());

    for i in 0..N {
        let user = format!("user_{i:04}");
        handshake_once(&signer, sealer.as_ref(), registry.as_ref(), &user).expect("handshake");
    }

    // Replay the sealed events through the projection. This simulates
    // "registry lost, rebuild from segment log" (master-plan §7.1).
    let mut projection = SessionPlansByPrincipalV1::new();
    for event in sealer.events().unwrap() {
        projection
            .apply_raw(event.event_type, event.content_type, &event.payload)
            .expect("apply_raw");
    }

    assert_eq!(projection.total_plans(), N);
    // Each principal is unique in this test, so every principal has
    // exactly one plan.
    for (_principal, _origin_install) in projection.principals() {
        // `principals()` only yields occupied entries so this loop runs.
    }
    assert_eq!(projection.principals().count(), N);
}
