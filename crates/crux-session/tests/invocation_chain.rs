// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! M4 chain-verification correspondence test.
//!
//! Master plan §12.1 Phase 4 gate: "10,000 MCP tool calls produce 10,000
//! receipts, all chain-verifiable to their plans." We run a scaled-down
//! version (500 calls across 5 plans, 100 calls each) to keep `cargo test`
//! fast; the chaining property is identical regardless of volume.

use std::collections::HashSet;

use corecrux_projections::{
    InvocationReceiptedV1, SessionPlanSealedV1, CONTENT_TYPE_SESSION_BIN_V1, EVT_INVOCATION_RECEIPTED_V1,
    EVT_SESSION_PLAN_SEALED_V1,
};
use crux_session::{
    handshake::random_ulid, invocation::MintInvocation, mint as mint_plan, mint_invocation_receipt, plan::ReceiptMode,
    verify_invocation_receipt, Budget, Channels, GraphHints, HandshakeInputs, HandshakeRequest, InMemoryRegistry,
    InMemorySealer, InProcessEd25519Signer, Passport, PlanSealer, RegistryEntry, SealedEvent, SessionPlan,
    SessionRegistry, DEFAULT_CATALOG,
};

fn build_plan() -> (SessionPlan, Vec<u8>) {
    let passport = Passport {
        principal_id: "tenant:cuecrux_ltd:myles".into(),
        tier: "team".into(),
        affinities: vec!["retrieval".into(), "journal".into(), "memory".into(), "proof".into()],
        denied_capabilities: None,
        grant_expansions: None,
        passport_receipt: None,
    };
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
        session_ttl_s: 3600,
        budget: Budget {
            tokens_cap: Some(100_000),
            crux_cap: Some(500),
            ttl_s: 3600,
        },
        origin: "core".into(),
        origin_install: None,
        intent_hint: None,
        now_ms: 1_745_000_000_000,
    };
    let signer = InProcessEd25519Signer::from_seed([42u8; 32], "test-signer");
    let sealed = mint_plan(
        request,
        HandshakeInputs {
            catalog: DEFAULT_CATALOG,
            enabled_feature_flags: &HashSet::new(),
            signer: &signer,
        },
    )
    .expect("mint plan");
    (sealed.plan, sealed.canonical_cbor)
}

fn seal_plan(plan: &SessionPlan, plan_cbor: &[u8], sealer: &dyn PlanSealer) {
    let event = SessionPlanSealedV1 {
        event_id: random_ulid(),
        plan_id: plan.plan_id,
        session_id: plan.session_id,
        principal_id: plan.passport.principal_id.clone(),
        origin: plan.origin.clone(),
        origin_install: plan.origin_install,
        minted_at_ms: plan.minted_at as i64,
        expires_at_ms: (plan.minted_at + plan.session_ttl_s * 1000) as i64,
        plan_receipt_hash: plan.receipt.hash,
        plan_receipt_signature: plan.receipt.signature,
        capability_graph_hash: plan.capability_graph_hash,
        plan_bytes_cbor: plan_cbor.to_vec(),
    };
    sealer
        .seal(&SealedEvent {
            event_type: EVT_SESSION_PLAN_SEALED_V1,
            content_type: CONTENT_TYPE_SESSION_BIN_V1,
            tenant_id: plan.origin.clone(),
            stream_type: "session-plans".into(),
            stream_id: plan.passport.principal_id.clone(),
            payload: event.encode_bin(),
        })
        .expect("seal plan");
}

#[test]
fn n_invocations_chain_verify_against_parent_plans() {
    const PLANS: usize = 5;
    const CALLS_PER_PLAN: usize = 100;

    let registry = InMemoryRegistry::new();
    let sealer = InMemorySealer::new();

    // Mint + seal PLANS session plans and stash them in the registry.
    let plans: Vec<(SessionPlan, Vec<u8>)> = (0..PLANS).map(|_| build_plan()).collect();
    for (plan, plan_cbor) in &plans {
        seal_plan(plan, plan_cbor, &sealer);
        registry
            .insert(RegistryEntry::from_plan(plan, plan_cbor.clone()))
            .expect("insert plan");
    }
    assert_eq!(sealer.len(), PLANS);
    assert_eq!(registry.active_count().unwrap(), PLANS);

    // For each plan, simulate CALLS_PER_PLAN tool invocations, each of
    // which mints a receipt AND seals an InvocationReceiptedV1 event.
    // Every capability + channel combination is from the plan's graph,
    // so all receipts should verify cleanly.
    let mut total_invocations = 0;
    for (plan, _) in &plans {
        for i in 0..CALLS_PER_PLAN {
            let cap = &plan.capability_graph[i % plan.capability_graph.len()];
            let receipt = mint_invocation_receipt(MintInvocation {
                invocation_id: random_ulid(),
                parent_plan: plan,
                capability: cap.cap.clone(),
                channel: cap.prefer.clone(),
                invoked_at_ms: plan.minted_at + (i as u64) * 100,
                completed_at_ms: plan.minted_at + (i as u64) * 100 + 50,
                input_hash: [(i as u8).wrapping_add(1); 32],
                output_hash: [(i as u8).wrapping_add(2); 32],
                outcome: "ok".into(),
                cost_crux: Some(1),
                signer_kid: None,
            });

            // (a) Seal an InvocationReceiptedV1 event — always-store for
            // invocations, mirroring M2's plan-sealed rule.
            let event = InvocationReceiptedV1 {
                event_id: random_ulid(),
                session_id: plan.session_id,
                capability: receipt.capability.clone(),
                channel: receipt.channel.clone(),
                invocation_at_ms: receipt.invoked_at as i64,
                invocation_receipt_hash: receipt.receipt_hash,
                parent_plan_receipt_hash: receipt.parent_plan_receipt_hash,
            };
            sealer
                .seal(&SealedEvent {
                    event_type: EVT_INVOCATION_RECEIPTED_V1,
                    content_type: CONTENT_TYPE_SESSION_BIN_V1,
                    tenant_id: plan.origin.clone(),
                    stream_type: "session-invocations".into(),
                    stream_id: plan.passport.principal_id.clone(),
                    payload: event.encode_bin(),
                })
                .expect("seal invocation");

            // (b) Independently verify the receipt against its parent plan
            // via the same code path the `POST /invocation/verify` endpoint
            // uses. All N receipts must chain.
            let verdict = verify_invocation_receipt(&receipt, plan);
            assert!(
                verdict.verified_overall(),
                "receipt {i} for plan {:?} failed to chain: {verdict:?}",
                plan.session_id
            );
            assert!(verdict.governance_faults.is_empty());
            total_invocations += 1;
        }
    }

    assert_eq!(total_invocations, PLANS * CALLS_PER_PLAN);
    // Sealer should hold PLANS + (PLANS * CALLS_PER_PLAN) events: the five
    // SessionPlanSealedV1 + 500 InvocationReceiptedV1.
    assert_eq!(sealer.len(), PLANS + (PLANS * CALLS_PER_PLAN));
}

#[test]
fn registry_reverse_lookup_finds_parent_plan() {
    let registry = InMemoryRegistry::new();
    let (plan, plan_cbor) = build_plan();
    registry
        .insert(RegistryEntry::from_plan(&plan, plan_cbor.clone()))
        .expect("insert");

    let found = registry
        .get_by_plan_hash(&plan.receipt.hash)
        .expect("lookup")
        .expect("entry");
    assert_eq!(found.session_id, plan.session_id);
    assert_eq!(found.plan_cbor, plan_cbor);

    let not_found = registry.get_by_plan_hash(&[0u8; 32]).expect("lookup").is_none();
    assert!(not_found);
}

#[test]
fn governance_fault_flags_but_does_not_reject() {
    let (plan, plan_cbor) = build_plan();
    let registry = InMemoryRegistry::new();
    registry
        .insert(RegistryEntry::from_plan(&plan, plan_cbor))
        .expect("insert");

    // Invoke a capability that is NOT in the plan's graph. Verifier
    // returns `verified=false` but the receipt is still recorded in the
    // sealer (audit sees the attempt) — master-plan §8.2.
    let mut receipt = mint_invocation_receipt(MintInvocation {
        invocation_id: random_ulid(),
        parent_plan: &plan,
        capability: "definitely_not_in_graph".into(),
        channel: "bulk".into(),
        invoked_at_ms: plan.minted_at + 1_000,
        completed_at_ms: plan.minted_at + 1_100,
        input_hash: [0x11; 32],
        output_hash: [0x22; 32],
        outcome: "ok".into(),
        cost_crux: None,
        signer_kid: None,
    });
    // A valid-mode receipt requires a verified parent; our receipt is
    // minted correctly otherwise.
    assert_eq!(plan.receipt.mode, ReceiptMode::Verified);
    assert!(receipt.receipt_hash != [0u8; 32]);
    receipt.cost_crux = None;

    let verdict = verify_invocation_receipt(&receipt, &plan);
    assert!(!verdict.capability_ok);
    assert!(!verdict.verified_overall());
    assert!(
        verdict
            .governance_faults
            .iter()
            .any(|f| f.starts_with("capability_not_in_graph")),
        "faults: {:?}",
        verdict.governance_faults
    );
}
