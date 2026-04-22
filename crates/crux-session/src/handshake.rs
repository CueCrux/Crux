// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Handshake service — mints a [`SessionPlan`] from a passport + hints.
//!
//! Pipeline:
//!
//! ```text
//!   (Passport, Hints, Channels, Catalog, Signer, Clock)
//!     ─► capability graph      (generator::generate_graph)
//!     ─► unsigned plan         (with zero hash + null signature)
//!     ─► BLAKE3 over zeroed    (receipt_hash)
//!     ─► sign (if available)   (receipt.signature / signer_kid)
//!     ─► sealed plan           (returned)
//!     ─► registry.insert       (caller's responsibility; see corecruxd
//!                                route for the full CE wiring)
//! ```
//!
//! The service has **no I/O** — it's a pure function over its inputs plus
//! a signer side-effect. Timing, registry writes, and segment-log sealing
//! are the caller's responsibility.

use std::collections::HashSet;

use rand::RngCore;

use crate::catalog::CatalogEntry;
use crate::error::SessionError;
use crate::generator::{generate_graph, GenerateInput, GraphHints};
use crate::plan::{Budget, Channels, Passport, ReceiptEnvelope, SessionPlan, SESSION_PLAN_VERSION, ULID_LEN};
use crate::receipt::plan_receipt_hash;
use crate::signer::PlanSigner;

#[derive(Debug, Clone)]
pub struct HandshakeRequest {
    pub passport: Passport,
    pub channels: Channels,
    pub hints: GraphHints,
    pub session_ttl_s: u64,
    pub budget: Budget,
    pub origin: String,
    pub origin_install: Option<[u8; 32]>,
    pub intent_hint: Option<String>,
    pub now_ms: u64,
}

pub struct HandshakeInputs<'a> {
    pub catalog: &'a [CatalogEntry],
    pub enabled_feature_flags: &'a HashSet<String>,
    pub signer: &'a dyn PlanSigner,
}

#[derive(Debug, Clone)]
pub struct SealedPlan {
    pub plan: SessionPlan,
    pub canonical_cbor: Vec<u8>,
}

pub fn mint(request: HandshakeRequest, inputs: HandshakeInputs<'_>) -> Result<SealedPlan, SessionError> {
    let graph = generate_graph(GenerateInput {
        catalog: inputs.catalog,
        passport: &request.passport,
        hints: &request.hints,
        crux_cap: request.budget.crux_cap,
        enabled_feature_flags: inputs.enabled_feature_flags,
        intent_table: None,
    });

    let plan_id = random_ulid();
    let session_id = random_ulid();

    // Mode is fixed before hashing because it's part of the hashed content
    // (only hash/signature/signer_kid are zeroed — master-plan §3.3).
    let mode = inputs.signer.mode();

    let mut plan = SessionPlan {
        plan_id,
        plan_version: SESSION_PLAN_VERSION,
        minted_at: request.now_ms,
        origin: request.origin,
        origin_install: request.origin_install,
        session_id,
        session_ttl_s: request.session_ttl_s,
        passport: request.passport,
        channels: request.channels,
        capability_graph: graph.capabilities,
        capability_graph_hash: graph.hash,
        budget: request.budget,
        receipt: ReceiptEnvelope {
            mode,
            hash: [0u8; 32],
            signature: None,
            signer_kid: None,
            parent_chain: None,
        },
        intent_hint: request.intent_hint,
    };

    let hash = plan_receipt_hash(&plan);
    plan.receipt.hash = hash;

    if let Some(signed) = inputs.signer.sign(&hash)? {
        plan.receipt.signature = Some(signed.signature);
        plan.receipt.signer_kid = Some(signed.signer_kid);
    }

    let canonical_cbor = plan.to_canonical_cbor();
    Ok(SealedPlan { plan, canonical_cbor })
}

/// Rough ULID: timestamp component omitted; 16 random bytes. Good enough
/// for unique id purposes within a single install; a full Monotonic-ULID is
/// a nice-to-have but not a schema-visible change.
pub fn random_ulid() -> [u8; ULID_LEN] {
    let mut out = [0u8; ULID_LEN];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::DEFAULT_CATALOG;
    use crate::plan::ReceiptMode;
    use crate::signer::{InProcessEd25519Signer, NullSigner};

    fn sample_request(passport: Passport, origin: &str) -> HandshakeRequest {
        HandshakeRequest {
            passport,
            channels: Channels {
                bulk: Some("h2://localhost:14801/v2".into()),
                mcp: "http://localhost:14801/mcp".into(),
            },
            hints: GraphHints {
                prefer_bulk: true,
                intent: None,
                max_capabilities: None,
            },
            session_ttl_s: 3600,
            budget: Budget {
                tokens_cap: None,
                crux_cap: None,
                ttl_s: 3600,
            },
            origin: origin.into(),
            origin_install: Some([0xAAu8; 32]),
            intent_hint: None,
            now_ms: 1_745_000_000_000,
        }
    }

    #[test]
    fn ce_mint_yields_local_mode() {
        let pp = Passport {
            principal_id: "ce:abc:user".into(),
            tier: "local".into(),
            affinities: vec!["*".into()],
            passport_receipt: None,
        };
        let flags = HashSet::new();
        let signer = NullSigner;
        let sealed = mint(
            sample_request(pp, "ce"),
            HandshakeInputs {
                catalog: DEFAULT_CATALOG,
                enabled_feature_flags: &flags,
                signer: &signer,
            },
        )
        .unwrap();
        assert_eq!(sealed.plan.receipt.mode, ReceiptMode::Local);
        assert!(sealed.plan.receipt.signature.is_none());
        assert!(sealed.plan.receipt.signer_kid.is_none());
        assert_eq!(sealed.plan.origin, "ce");
        assert_ne!(sealed.plan.receipt.hash, [0u8; 32]);
    }

    #[test]
    fn hosted_mint_yields_verified_mode_with_signature() {
        let pp = Passport {
            principal_id: "tenant:co:user".into(),
            tier: "team".into(),
            affinities: vec!["retrieval".into(), "proof".into(), "memory".into()],
            passport_receipt: None,
        };
        let flags = HashSet::new();
        let signer = InProcessEd25519Signer::from_seed([7u8; 32], "test-kid");
        let sealed = mint(
            sample_request(pp, "core"),
            HandshakeInputs {
                catalog: DEFAULT_CATALOG,
                enabled_feature_flags: &flags,
                signer: &signer,
            },
        )
        .unwrap();
        assert_eq!(sealed.plan.receipt.mode, ReceiptMode::Verified);
        assert!(sealed.plan.receipt.signature.is_some());
        assert_eq!(sealed.plan.receipt.signer_kid.as_deref(), Some("test-kid"));

        // Signature must verify against the signer's public key.
        crate::receipt::verify_plan_signature(&sealed.plan, &signer.verifying_key_bytes()).expect("signature verify");
    }
}
