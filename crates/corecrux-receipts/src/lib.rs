// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! CoreCrux v3 Phase 8: receipts (bytes-first) + signature verification + export bundles.
//!
//! Invariants (per Phase 8 doc):
//! - Receipt body is stored/returned as opaque canonical bytes (typically CBOR).
//! - Hashing/verification operates over the stored bytes exactly (no re-serialization).
//! - Verification output is derived state (rebuildable).

mod approval_decision_v1;
mod audit_bundle_v1;
mod body_v1;
mod candidate_digest_v1;
mod export_v1;
mod forget_v1;
mod keyring_v1;
mod memory_use_v1;
mod store_v1;
mod subject_index_v1;
mod verify_v1;

pub use approval_decision_v1::{
    assert_approval_decision_kind_v1, build_approval_decision_body_v1, sign_approval_decision_v1,
    ApprovalDecisionBodyInputV1, ApprovalDecisionV1, ApprovalRiskTierV1, APPROVAL_DECISION_BODY_SCHEMA_V1,
    APPROVAL_DECISION_KIND_V1,
};
pub use audit_bundle_v1::{
    build_bundle_v1, decode_receipts_cbor, verify_bundle_v1, AuditBundleError, AuditBundleManifestV1,
    AuditBundleScopeV1, AuditEventV1, AuditReceiptRefV1, BuildBundleInputV1, BuiltBundleV1, VerifyReportV1,
    BUNDLE_FORMAT_VERSION, EVENTS_FILENAME, MANIFEST_FILENAME, RECEIPTS_FILENAME,
};
pub use body_v1::{extract_body_index_v1, extract_linked_receipts_v1, ReceiptBodyIndexV1};
pub use export_v1::{
    build_receipt_export_v1, BuildReceiptExportInput, ExportError, ExportFileV1, ExportFormatV1, ExportRedactionV1,
    ReceiptEventHeaderRefV1, ReceiptExportBundleV1, ReceiptExportIncludeV1, ReceiptExportOptionsV1,
    ReplayExportManifestV1,
};
pub use forget_v1::{
    blake3_hex, decode_forget_body_v1, decode_permanent_purge_body_v1, encode_forget_body_v1,
    encode_permanent_purge_body_v1, extract_forget_summary_v1, ForgetFactRefV1, ForgetReceiptBodyV1,
    ForgetReceiptError, ForgetReceiptSummaryV1, ForgetScopeV1, PermanentPurgeReceiptBodyV1,
    CONTENT_TYPE_FORGET_BODY_V1, CONTENT_TYPE_PERMANENT_PURGE_BODY_V1, EVT_RECEIPT_FORGET_BODY_V1,
    EVT_RECEIPT_PERMANENT_PURGE_BODY_V1, SCHEMA_FORGET_BODY_V1, SCHEMA_PERMANENT_PURGE_BODY_V1,
};
pub use keyring_v1::{Ed25519KeyEntryV1, Ed25519KeyRingV1, KeyRingError};
pub use memory_use_v1::{
    assert_memory_use_kind_v1, build_memory_use_body_v1, extract_memory_use_entries_v1, filter_reserved_entries,
    is_reserved_entity_prefix, sign_memory_use_v1, MemoryUseBodyInputV1, MemoryUseEntryV1, MemoryUseIntentV1,
    MEMORY_USE_BODY_SCHEMA_V1, MEMORY_USE_KIND_V1, RESERVED_ENTITY_PREFIXES_V1,
};
pub use store_v1::{
    load_verification_report_v1, store_verification_report_v1, verification_report_path_v1, ReceiptStoreError,
};
pub use subject_index_v1::{
    resolve_subject_receipt_id_v1, subject_index_path_v1, update_subject_index_v1, ReceiptSubjectIndexV1,
    ReceiptSubjectLatestV1, SubjectResolveModeV1,
};
pub use verify_v1::{verify_receipt_v1, ReceiptSigV1, VerificationReportV1, VerifyErrorCodeV1, VerifyReceiptInput};

pub const STREAM_TYPE_RECEIPT: &str = "receipt";
pub const EVT_RECEIPT_BODY_V1: &str = "receipt.body.v1";
pub const EVT_RECEIPT_SIG_V1: &str = "receipt.sig.v1";

pub const CONTENT_TYPE_RECEIPT_BODY_V1: &str = "application/cbor; profile=cuecrux-receipt-body-v1";
pub const CONTENT_TYPE_RECEIPT_SIG_V1: &str = "application/cbor; profile=cuecrux-receipt-sig-v1";

// Agent observation stream (Phase 2 M5e — multi-provider capture).
//
// The local daemon writes chained JSONL today (each record carries
// `prev_hash` + `seq` so sequence-level tamper-evident audit works without
// the dataplane pool). The constants below are the canonical stream-type
// + event-type tags for a future Tier 2+ deployment that replays chained
// JSONL into the same `PoolBackedHttpDataplane` infrastructure used by
// receipts. Declaring them here keeps the schema in one place even though
// only chained-JSONL writes are wired in the community edition.
pub const STREAM_TYPE_AGENT_OBSERVATION: &str = "agent.observation";
pub const EVT_AGENT_OBSERVATION_BODY_V1: &str = "agent.observation.body.v1";
pub const EVT_AGENT_OBSERVATION_SIG_V1: &str = "agent.observation.sig.v1";

pub const CONTENT_TYPE_AGENT_OBSERVATION_BODY_V1: &str = "application/json; profile=cuecrux-agent-observation-body-v1";
pub const CONTENT_TYPE_AGENT_OBSERVATION_SIG_V1: &str = "application/json; profile=cuecrux-agent-observation-sig-v1";

#[cfg(test)]
mod tests;
