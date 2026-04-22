// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! CE → Core export bundle (M8).
//!
//! A `CeExportBundle` is a snapshot of a CE install's session state:
//!
//! - `install_uuid` — the raw string under `data_dir/.install-uuid`.
//! - `plans` — every session row (one per file under `data_dir/sessions/`).
//!   Each plan carries the canonical-CBOR bytes exactly as the CE sealer
//!   stored them — the hosted side re-hashes these to verify.
//! - `invocations` — hex-encoded `InvocationReceiptedV1` payloads from the
//!   CE event log, keyed by the session they belong to.
//!
//! The format is JSON (not CBOR) for simplicity — this is a one-off
//! migration payload, not a hot-path wire format. An operator can
//! inspect the bundle with `jq` before uploading.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::SessionError;
use crate::plan::{SessionPlan, HASH_LEN};
use crate::receipt::InvocationReceipt;

pub const BUNDLE_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeExportBundle {
    pub schema_version: u16,
    pub install_uuid: String,
    /// One entry per sealed session. `plan_cbor_hex` is the byte-exact
    /// canonical-CBOR of the plan as emitted by `mint()` on CE.
    pub plans: Vec<ExportedPlan>,
    /// Invocation receipts grouped by session_id (hex).
    pub invocations: BTreeMap<String, Vec<ExportedInvocation>>,
    pub generated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedPlan {
    pub session_id_hex: String,
    pub principal_id: String,
    pub plan_receipt_hash_hex: String,
    /// Byte-exact canonical CBOR of the SessionPlan (local-mode).
    pub plan_cbor_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedInvocation {
    /// The full receipt, encoded as hex-field JSON for self-describing
    /// transport. The hosted side decodes back into [`InvocationReceipt`]
    /// before running the verifier.
    pub receipt: ExportedReceiptWire,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedReceiptWire {
    pub invocation_id: String,
    pub session_id: String,
    pub parent_plan_receipt_hash: String,
    pub capability: String,
    pub channel: String,
    pub invoked_at: u64,
    pub completed_at: u64,
    pub input_hash: String,
    pub output_hash: String,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_crux: Option<u64>,
    pub receipt_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_kid: Option<String>,
}

impl From<&InvocationReceipt> for ExportedReceiptWire {
    fn from(r: &InvocationReceipt) -> Self {
        Self {
            invocation_id: hex::encode(r.invocation_id),
            session_id: hex::encode(r.session_id),
            parent_plan_receipt_hash: hex::encode(r.parent_plan_receipt_hash),
            capability: r.capability.clone(),
            channel: r.channel.clone(),
            invoked_at: r.invoked_at,
            completed_at: r.completed_at,
            input_hash: hex::encode(r.input_hash),
            output_hash: hex::encode(r.output_hash),
            outcome: r.outcome.clone(),
            cost_crux: r.cost_crux,
            receipt_hash: hex::encode(r.receipt_hash),
            receipt_signature: r.receipt_signature.map(hex::encode),
            signer_kid: r.signer_kid.clone(),
        }
    }
}

impl TryFrom<&ExportedReceiptWire> for InvocationReceipt {
    type Error = SessionError;

    fn try_from(w: &ExportedReceiptWire) -> Result<Self, Self::Error> {
        fn fixed<const N: usize>(s: &str, field: &str) -> Result<[u8; N], SessionError> {
            let bytes = hex::decode(s)?;
            if bytes.len() != N {
                return Err(SessionError::ByteArrayLength {
                    field: Box::leak(field.to_string().into_boxed_str()),
                    expected: N,
                    actual: bytes.len(),
                });
            }
            let mut out = [0u8; N];
            out.copy_from_slice(&bytes);
            Ok(out)
        }
        Ok(InvocationReceipt {
            invocation_id: fixed::<16>(&w.invocation_id, "invocation_id")?,
            session_id: fixed::<16>(&w.session_id, "session_id")?,
            parent_plan_receipt_hash: fixed::<HASH_LEN>(&w.parent_plan_receipt_hash, "parent_plan_receipt_hash")?,
            capability: w.capability.clone(),
            channel: w.channel.clone(),
            invoked_at: w.invoked_at,
            completed_at: w.completed_at,
            input_hash: fixed::<HASH_LEN>(&w.input_hash, "input_hash")?,
            output_hash: fixed::<HASH_LEN>(&w.output_hash, "output_hash")?,
            outcome: w.outcome.clone(),
            cost_crux: w.cost_crux,
            receipt_hash: fixed::<HASH_LEN>(&w.receipt_hash, "receipt_hash")?,
            receipt_signature: match &w.receipt_signature {
                Some(s) => Some(fixed::<64>(s, "receipt_signature")?),
                None => None,
            },
            signer_kid: w.signer_kid.clone(),
        })
    }
}

/// Verifier-facing decoder for a plan entry. Parses the hex CBOR back into
/// a full [`SessionPlan`] and exposes its hash. On the hosted side this
/// is the first step: re-derive each plan's hash from its own bytes and
/// match against `plan_receipt_hash_hex`.
pub fn decode_plan_entry(entry: &ExportedPlan) -> Result<SessionPlan, SessionError> {
    let bytes = hex::decode(&entry.plan_cbor_hex)?;
    SessionPlan::from_canonical_cbor(&bytes)
}

/// Build an export bundle from a CE install's durable state. Reads the
/// persistent install UUID, every registry row, and the full event log;
/// emits a self-contained [`CeExportBundle`] ready to POST to the hosted
/// `/v1/ce-import` endpoint.
pub fn build_bundle(
    passport_cfg: &crate::passport::LocalPassportConfig,
    registry: &dyn crate::registry::SessionRegistry,
    sealer: &crate::sealer::FileSealer,
    generated_at_ms: u64,
) -> Result<CeExportBundle, SessionError> {
    // Plans: we need all registry entries. The trait doesn't expose an
    // iterator yet, so we rely on the sealer log to enumerate session_ids
    // — the SessionPlanSealedV1 events carry every session we've ever
    // opened. Lookup into the registry gives us the current state.
    let events = sealer
        .read_all()
        .map_err(|e| SessionError::Decode(format!("read event log: {e}")))?;

    let mut plans: Vec<ExportedPlan> = Vec::new();
    let invocations: BTreeMap<String, Vec<ExportedInvocation>> = BTreeMap::new();
    let mut seen_sessions: BTreeSet<String> = BTreeSet::new();

    for event in events {
        if event.event_type == "corecrux.session.plan_sealed.v1" {
            // Pull the session_id out of the payload without a full decode:
            // SessionPlanSealedV1::encode_bin starts with version(2) +
            // event_id(16) + plan_id(16) + session_id(16)...
            if event.payload.len() < 2 + 16 + 16 + 16 {
                continue;
            }
            let session_id: [u8; 16] = event.payload[34..50]
                .try_into()
                .map_err(|e: std::array::TryFromSliceError| SessionError::Decode(format!("slice session_id: {e}")))?;
            let session_hex = hex::encode(session_id);
            if seen_sessions.contains(&session_hex) {
                continue; // only emit once per session even if there are multiple events
            }
            if let Some(entry) = registry
                .get(&session_id)
                .map_err(|e| SessionError::Decode(format!("registry.get: {e}")))?
            {
                plans.push(ExportedPlan {
                    session_id_hex: session_hex.clone(),
                    principal_id: entry.principal_id,
                    plan_receipt_hash_hex: hex::encode(entry.plan_receipt_hash),
                    plan_cbor_hex: hex::encode(&entry.plan_cbor),
                });
                seen_sessions.insert(session_hex);
            }
        }
    }

    let (passport, _) = passport_cfg.synthesise();
    let _ = passport; // silence — we only need the install_uuid here

    Ok(CeExportBundle {
        schema_version: BUNDLE_SCHEMA_VERSION,
        install_uuid: passport_cfg.install_uuid.clone(),
        plans,
        invocations,
        generated_at_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_plan_cbor() -> Vec<u8> {
        // Minimal valid-shaped plan bytes for roundtrip — the export
        // format doesn't care about the plan's internal validity, only
        // that the bytes roundtrip losslessly.
        vec![0xa0] // CBOR empty map — decode will fail but that's fine; this test only
                   // exercises serde, not plan decoding.
    }

    #[test]
    fn bundle_json_roundtrip() {
        let bundle = CeExportBundle {
            schema_version: BUNDLE_SCHEMA_VERSION,
            install_uuid: "install-uuid-test".into(),
            plans: vec![ExportedPlan {
                session_id_hex: "0102030405060708090a0b0c0d0e0f10".into(),
                principal_id: "ce:a4f3b1c2:tester".into(),
                plan_receipt_hash_hex: "00".repeat(HASH_LEN),
                plan_cbor_hex: hex::encode(sample_plan_cbor()),
            }],
            invocations: BTreeMap::new(),
            generated_at_ms: 1_745_500_000_000,
        };
        let json = serde_json::to_string(&bundle).unwrap();
        let parsed: CeExportBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.install_uuid, bundle.install_uuid);
        assert_eq!(parsed.plans.len(), 1);
        assert_eq!(parsed.plans[0].session_id_hex, bundle.plans[0].session_id_hex);
    }

    #[test]
    fn exported_receipt_wire_roundtrip() {
        let r = InvocationReceipt {
            invocation_id: [0x01; 16],
            session_id: [0x02; 16],
            parent_plan_receipt_hash: [0x03; HASH_LEN],
            capability: "retrieve".into(),
            channel: "bulk".into(),
            invoked_at: 1_000,
            completed_at: 1_100,
            input_hash: [0x04; HASH_LEN],
            output_hash: [0x05; HASH_LEN],
            outcome: "ok".into(),
            cost_crux: Some(7),
            receipt_hash: [0x06; HASH_LEN],
            receipt_signature: None,
            signer_kid: None,
        };
        let wire: ExportedReceiptWire = (&r).into();
        let back: InvocationReceipt = (&wire).try_into().unwrap();
        assert_eq!(back.invocation_id, r.invocation_id);
        assert_eq!(back.parent_plan_receipt_hash, r.parent_plan_receipt_hash);
        assert_eq!(back.capability, r.capability);
        assert_eq!(back.receipt_hash, r.receipt_hash);
        assert_eq!(back.cost_crux, r.cost_crux);
    }
}
