// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Invocation-receipt minting + verification (master-plan §8).
//!
//! Every Layer 2 bulk call and every Layer 3 MCP tool call executed under
//! an active session produces an [`InvocationReceipt`]. This module:
//!
//! - [`mint_invocation_receipt`] — builds a fresh `InvocationReceipt` for a
//!   just-completed call, chained to the parent plan by
//!   `parent_plan_receipt_hash`.
//! - [`verify_invocation_receipt`] — returns a [`InvocationVerdict`] per
//!   master-plan §8.2. Violations of the `capability` / `channel` checks
//!   are **flagged, not rejected** — audit must see the attempt.
//! - `build_invocation_sealed_event` — builds a
//!   [`crate::sealer::SealedEvent`] ready to hand to a segment sealer so
//!   the invocation lands in the segment log.

use crate::plan::{SessionPlan, HASH_LEN, ULID_LEN};
use crate::receipt::InvocationReceipt;

pub const EVT_INVOCATION_RECEIPTED_V1: &str = "corecrux.session.invocation_receipted.v1";
pub const CONTENT_TYPE_SESSION_BIN_V1: &str = "application/x-corecrux-session-bin-v1";

#[derive(Debug, Clone)]
pub struct MintInvocation<'a> {
    pub invocation_id: [u8; ULID_LEN],
    pub parent_plan: &'a SessionPlan,
    pub capability: String,
    pub channel: String,
    pub invoked_at_ms: u64,
    pub completed_at_ms: u64,
    pub input_hash: [u8; HASH_LEN],
    pub output_hash: [u8; HASH_LEN],
    pub outcome: String,
    pub cost_crux: Option<u64>,
    pub signer_kid: Option<String>,
}

pub fn mint_invocation_receipt(input: MintInvocation<'_>) -> InvocationReceipt {
    let mut receipt = InvocationReceipt {
        invocation_id: input.invocation_id,
        session_id: input.parent_plan.session_id,
        parent_plan_receipt_hash: input.parent_plan.receipt.hash,
        capability: input.capability,
        channel: input.channel,
        invoked_at: input.invoked_at_ms,
        completed_at: input.completed_at_ms,
        input_hash: input.input_hash,
        output_hash: input.output_hash,
        outcome: input.outcome,
        cost_crux: input.cost_crux,
        receipt_hash: [0u8; HASH_LEN],
        receipt_signature: None,
        signer_kid: input.signer_kid,
    };
    receipt.receipt_hash = receipt.compute_hash();
    receipt
}

/// Verdict produced by [`verify_invocation_receipt`].
///
/// `integrity_ok` covers checks (1) + (2) from master-plan §8.2: the
/// receipt's own hash matches its canonical bytes, and the
/// `parent_plan_receipt_hash` matches the supplied plan's hash.
///
/// `capability_ok` / `channel_ok` cover (3) + (4). When either is `false`,
/// the receipt is **flagged, not rejected** — `verified_overall` is only
/// `true` when integrity, capability, and channel all pass. Flagged
/// receipts are preserved as audit evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvocationVerdict {
    pub integrity_ok: bool,
    pub capability_ok: bool,
    pub channel_ok: bool,
    pub governance_faults: Vec<String>,
}

impl InvocationVerdict {
    pub fn verified_overall(&self) -> bool {
        self.integrity_ok && self.capability_ok && self.channel_ok
    }
}

pub fn verify_invocation_receipt(receipt: &InvocationReceipt, plan: &SessionPlan) -> InvocationVerdict {
    let mut faults: Vec<String> = Vec::new();

    // (1) Receipt's own hash must match a re-encode with the hash/sig/kid zeroed.
    let recomputed = receipt.compute_hash();
    let own_hash_ok = recomputed == receipt.receipt_hash;
    if !own_hash_ok {
        faults.push("receipt_hash_mismatch".into());
    }

    // (2) parent_plan_receipt_hash must match the supplied plan's receipt hash.
    let parent_link_ok = receipt.parent_plan_receipt_hash == plan.receipt.hash;
    if !parent_link_ok {
        faults.push("parent_plan_receipt_hash_mismatch".into());
    }

    // (3) capability must be in the plan's capability_graph.
    let cap = plan.capability_graph.iter().find(|c| c.cap == receipt.capability);
    let capability_ok = cap.is_some();
    if !capability_ok {
        faults.push(format!("capability_not_in_graph:{}", receipt.capability));
    }

    // (4) channel must match the capability's `prefer` hint, with mcp as
    // always-allowed fallback (per master-plan §8.2). If the capability is
    // missing (3 already failed), channel check is not meaningful.
    let channel_ok = match cap {
        Some(c) => receipt.channel == c.prefer || receipt.channel == "mcp",
        None => false,
    };
    if !channel_ok && capability_ok {
        // Only emit a channel fault when capability was found; otherwise the
        // capability fault subsumes it.
        if let Some(c) = cap {
            faults.push(format!(
                "channel_mismatch:expected={}_got={}",
                c.prefer, receipt.channel
            ));
        }
    }

    InvocationVerdict {
        integrity_ok: own_hash_ok && parent_link_ok,
        capability_ok,
        channel_ok,
        governance_faults: faults,
    }
}

/// Build a [`crate::sealer::SealedEvent`] carrying an
/// [`InvocationReceipt`] serialized via the binary
/// `corecrux-projections::InvocationReceiptedV1` schema.
///
/// This is the event that lands in the segment log after a tool call
/// completes. The caller ties it through their segment sealer; we keep
/// the encoding decoupled from the projection crate here and leave the
/// actual wire-format encoding to the caller (corecruxd / VaultCrux).
/// A small helper in each of those crates turns this `InvocationReceipt`
/// into the `InvocationReceiptedV1` wire bytes.
pub fn invocation_event_key(receipt: &InvocationReceipt) -> InvocationEventKey {
    InvocationEventKey {
        event_type: EVT_INVOCATION_RECEIPTED_V1,
        content_type: CONTENT_TYPE_SESSION_BIN_V1,
        session_id: receipt.session_id,
        capability: receipt.capability.clone(),
    }
}

#[derive(Debug, Clone)]
pub struct InvocationEventKey {
    pub event_type: &'static str,
    pub content_type: &'static str,
    pub session_id: [u8; ULID_LEN],
    pub capability: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::random_ulid;
    use crate::plan::{
        Budget, Capability, Channels, ImplPath, Passport, ReceiptEnvelope, ReceiptMode, SessionPlan,
        SESSION_PLAN_VERSION,
    };
    use crate::receipt::plan_receipt_hash;

    fn sample_plan() -> SessionPlan {
        let mut plan = SessionPlan {
            plan_id: [1u8; 16],
            plan_version: SESSION_PLAN_VERSION,
            minted_at: 1_000_000,
            origin: "ce".into(),
            origin_install: Some([0xAA; 32]),
            session_id: [2u8; 16],
            session_ttl_s: 3600,
            passport: Passport {
                principal_id: "ce:test:tester".into(),
                tier: "local".into(),
                affinities: vec!["*".into()],
                passport_receipt: None,
            },
            channels: Channels {
                bulk: Some("h2://localhost:14801/v2".into()),
                mcp: "http://localhost:14800/mcp".into(),
            },
            capability_graph: vec![
                Capability {
                    cap: "retrieve".into(),
                    prefer: "bulk".into(),
                    shape: "stream<Chunk>".into(),
                    min_tier: None,
                    cost_class: "metered".into(),
                    impl_path: ImplPath { ce: None, core: None },
                },
                Capability {
                    cap: "journal_append".into(),
                    prefer: "mcp".into(),
                    shape: "Receipt".into(),
                    min_tier: None,
                    cost_class: "free".into(),
                    impl_path: ImplPath { ce: None, core: None },
                },
            ],
            capability_graph_hash: [0xC0; 32],
            budget: Budget {
                tokens_cap: None,
                crux_cap: None,
                ttl_s: 3600,
            },
            receipt: ReceiptEnvelope {
                mode: ReceiptMode::Local,
                hash: [0u8; 32],
                signature: None,
                signer_kid: None,
                parent_chain: None,
            },
            intent_hint: None,
        };
        plan.receipt.hash = plan_receipt_hash(&plan);
        plan
    }

    fn ok_receipt(plan: &SessionPlan, cap: &str, chan: &str) -> InvocationReceipt {
        mint_invocation_receipt(MintInvocation {
            invocation_id: random_ulid(),
            parent_plan: plan,
            capability: cap.to_string(),
            channel: chan.to_string(),
            invoked_at_ms: 1_100_000,
            completed_at_ms: 1_100_100,
            input_hash: [0x11; 32],
            output_hash: [0x22; 32],
            outcome: "ok".to_string(),
            cost_crux: None,
            signer_kid: None,
        })
    }

    #[test]
    fn minted_receipt_self_verifies() {
        let plan = sample_plan();
        let receipt = ok_receipt(&plan, "retrieve", "bulk");
        let verdict = verify_invocation_receipt(&receipt, &plan);
        assert!(verdict.verified_overall(), "verdict: {verdict:?}");
        assert!(verdict.governance_faults.is_empty());
    }

    #[test]
    fn mcp_fallback_channel_accepted_for_bulk_capability() {
        let plan = sample_plan();
        // retrieve's prefer = "bulk", but mcp is always allowed as fallback.
        let receipt = ok_receipt(&plan, "retrieve", "mcp");
        let verdict = verify_invocation_receipt(&receipt, &plan);
        assert!(verdict.channel_ok);
        assert!(verdict.verified_overall());
    }

    #[test]
    fn missing_capability_flags_governance_fault() {
        let plan = sample_plan();
        let receipt = ok_receipt(&plan, "not_in_graph", "mcp");
        let verdict = verify_invocation_receipt(&receipt, &plan);
        assert!(!verdict.capability_ok);
        assert!(!verdict.verified_overall());
        assert!(verdict
            .governance_faults
            .iter()
            .any(|f| f.starts_with("capability_not_in_graph")));
    }

    #[test]
    fn wrong_channel_for_mcp_only_capability_flags_fault() {
        let plan = sample_plan();
        // journal_append's prefer = "mcp"; using anything other than mcp is
        // a governance fault (bulk is not the declared channel and it's not
        // the universal fallback).
        let receipt = ok_receipt(&plan, "journal_append", "bulk");
        let verdict = verify_invocation_receipt(&receipt, &plan);
        assert!(!verdict.channel_ok);
        assert!(!verdict.verified_overall());
        assert!(verdict
            .governance_faults
            .iter()
            .any(|f| f.starts_with("channel_mismatch")));
    }

    #[test]
    fn tamper_with_parent_plan_hash_breaks_integrity() {
        let plan = sample_plan();
        let mut receipt = ok_receipt(&plan, "retrieve", "bulk");
        // Flip one byte in the parent hash.
        receipt.parent_plan_receipt_hash[0] ^= 0x01;
        // The receipt's own hash covered the tampered parent hash, so the
        // integrity check fires on (2) parent_plan_receipt_hash_mismatch.
        // We don't re-seal the receipt_hash, so the own-hash check still
        // passes for the UNTAMPERED bytes — but the parent link is
        // independent of the own-hash check and fails here.
        let verdict = verify_invocation_receipt(&receipt, &plan);
        assert!(!verdict.integrity_ok);
        assert!(verdict
            .governance_faults
            .iter()
            .any(|f| f == "parent_plan_receipt_hash_mismatch"));
    }

    #[test]
    fn tamper_with_receipt_own_hash_is_detected() {
        let plan = sample_plan();
        let mut receipt = ok_receipt(&plan, "retrieve", "bulk");
        receipt.receipt_hash[0] ^= 0x01;
        let verdict = verify_invocation_receipt(&receipt, &plan);
        assert!(!verdict.integrity_ok);
        assert!(verdict.governance_faults.iter().any(|f| f == "receipt_hash_mismatch"));
    }
}
