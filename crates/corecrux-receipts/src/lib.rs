// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

#![deny(clippy::unwrap_used, clippy::expect_used)]

//! CoreCrux v3 Phase 8: receipts (bytes-first) + signature verification + export bundles.
//!
//! Invariants (per Phase 8 doc):
//! - Receipt body is stored/returned as opaque canonical bytes (typically CBOR).
//! - Hashing/verification operates over the stored bytes exactly (no re-serialization).
//! - Verification output is derived state (rebuildable).

mod approval_decision_v1;
mod audit_bundle_v1;
mod audit_gap_v1;
mod audit_signing_key;
mod body_v1;
mod c2pa_chain_trust_v1;
mod c2pa_manifest_v1;
mod candidate_digest_v1;
mod chain_reanchor_v1;
mod cose_sign1_v1;
mod crypto_shred_v1;
mod export_v1;
mod forget_v1;
mod identity_v1;
mod keyring_v1;
mod memory_use_v1;
mod observation_envelope;
mod store_v1;
mod stream_v1;
mod subject_index_v1;
mod usage_receipt_v1;
pub mod vault_pki_x509_signer;
mod verify_v1;
mod witness_v1;

pub use approval_decision_v1::{
    assert_approval_decision_kind_v1, build_approval_decision_body_v1, sign_approval_decision_v1,
    ApprovalDecisionBodyInputV1, ApprovalDecisionV1, ApprovalRiskTierV1, APPROVAL_DECISION_BODY_SCHEMA_V1,
    APPROVAL_DECISION_KIND_V1,
};
pub use audit_bundle_v1::{
    build_bundle_v1, decode_receipts_cbor, verify_bundle_v1, verify_bundle_with_trust_roots_v1, AuditBundleError,
    AuditBundleKeyClassV1, AuditBundleManifestV1, AuditBundleScopeV1, AuditEventV1, AuditReceiptRefV1,
    BuildBundleInputV1, BuiltBundleV1, VerifyReportV1, BUNDLE_FORMAT_VERSION, EVENTS_FILENAME, MANIFEST_FILENAME,
    RECEIPTS_FILENAME,
};
pub use audit_gap_v1::{
    assert_chain_reanchor_kind_v1, assert_consolidation_kind_v1, assert_coverage_attestation_kind_v1,
    assert_coverage_window_kind_v1, assert_model_invocation_kind_v1, assert_redaction_receipt_kind_v1,
    build_chain_reanchor_body_v1, build_consolidation_body_v1, build_coverage_attestation_body_v1,
    build_coverage_window_body_v1, build_model_invocation_body_v1, build_redaction_receipt_body_v1,
    coverage_window_chain_fold_v1, coverage_window_chain_head_hex_v1, coverage_window_report_canonical_json_v1,
    sign_chain_reanchor_v1, sign_consolidation_v1, sign_coverage_attestation_v1, sign_coverage_window_v1,
    sign_model_invocation_v1, sign_redaction_receipt_v1, verify_chain_reanchor_body_v1, verify_coverage_window_body_v1,
    ChainReanchorBodyInputV1, ConsolidationBodyInputV1, CoverageAttestationBodyInputV1, CoverageWindowBodyInputV1,
    CoverageWindowCountsV1, CoverageWindowReportV1, ModelInvocationBodyInputV1, RedactionReceiptBodyInputV1,
    AUDIT_GAP_BODY_SCHEMA_V1, CHAIN_REANCHOR_KIND_V1, CONSOLIDATION_KIND_V1, COVERAGE_ATTESTATION_KIND_V1,
    COVERAGE_WINDOW_KIND_V1, COVERAGE_WINDOW_REPORT_SCHEMA_V1, MODEL_INVOCATION_KIND_V1, REDACTION_RECEIPT_KIND_V1,
};
pub use audit_signing_key::{
    persistent_audit_export_signing_key_path, resolve_audit_export_signing_key, AuditSigningKeyError,
    ResolvedAuditSigningKey, AUDIT_EXPORT_SIGNING_KEY_ENV, AUDIT_EXPORT_SIGNING_KEY_FILENAME,
    AUDIT_EXPORT_SIGNING_KEY_ID_ENV,
};
pub use body_v1::{extract_body_index_v1, extract_linked_receipts_v1, ReceiptBodyIndexV1};
pub use c2pa_chain_trust_v1::validate_c2pa_chain_to_anchor_v1;
pub use c2pa_manifest_v1::{
    assert_crown_receipt_id_v1, build_c2pa_manifest_v1, c2pa_x5chain_der_v1, canonical_body_bytes_v1, ed25519_signer,
    inspect_c2pa_leaf_certificate_v1, parse_jumbf_base64, sign_c2pa_manifest_v1, sign_c2pa_manifest_via_signer,
    verify_c2pa_manifest_v1, verify_c2pa_signed_manifest_es256_v1, ByokP256Signer, C2paActionV1, C2paLeafCertificateV1,
    C2paManifestError, C2paManifestInputV1, C2paManifestV1, C2paSignedManifestV1, C2paSigner, C2paVerificationReportV1,
    SignedManifestParts, C2PA_ACTION_CREATED, C2PA_MANIFEST_SCHEMA_V1, C2PA_SPEC_VERSION, CUECRUX_CROWN_RECEIPT_LABEL,
    DIGITAL_SOURCE_TYPE_AI, SOFTWARE_AGENT_DEFAULT,
};
pub use chain_reanchor_v1::{
    assert_chain_signature_reanchor_kind_v1, build_chain_signature_reanchor_body_v1,
    sign_chain_signature_reanchor_hybrid_v1, sign_chain_signature_reanchor_v1,
    verify_chain_signature_reanchor_hybrid_v1, verify_chain_signature_reanchor_v1, ChainSignatureReanchorBodyInputV1,
    ChainSignatureReanchorVerifyReportV1, ReanchorSigningKeyV1, ReanchorVerifyingKeyV1, ALG_ED25519_V1,
    ALG_P256_ECDSA_SHA256_V1, CHAIN_SIGNATURE_REANCHOR_BODY_SCHEMA_V1, CHAIN_SIGNATURE_REANCHOR_KIND_V1,
};
pub use cose_sign1_v1::{
    decode_cose_sign1, encode_cose_sign1_v1, verify_cose_sign1, CoseProtectedHeaderV1, CoseSign1Error,
    CrownCandidateEntryV1, CrownCounterfactualV1, CrownFusionV1, CrownKnowledgeStateCursorV1, CrownReceiptV1,
    CrownRetrievalV1, CrownSelectionV1, CrownTimingsV1, DecodedCoseSign1V1, TextOrNullV1, VerifiedCoseSign1V1,
    COSE_ALG_EDDSA, COSE_SIGN1_CBOR_TAG, CROWN_RECEIPT_CBOR_CONTENT_TYPE,
};
pub use crypto_shred_v1::{
    build_crypto_shred_destroy_marker_v1, open_crypto_shred_payload_v1, seal_crypto_shred_payload_v1,
    subject_cek_commitment_v1, CryptoShredDestroyMarkerInputV1, CryptoShredDestroyMarkerV1, CryptoShredEnvelopeV1,
    CryptoShredError, CryptoShredSealInputV1, CRYPTO_SHRED_DESTROY_ATTESTED_STATE_V1,
    CRYPTO_SHRED_DESTROY_MARKER_SCHEMA_V1, CRYPTO_SHRED_DESTROY_REQUESTED_STATE_V1, CRYPTO_SHRED_ENVELOPE_SCHEMA_V1,
    CRYPTO_SHRED_METHOD_V1,
};
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
pub use identity_v1::{
    decode_passport_link_device_body_v1, decode_passport_merge_body_v1, decode_passport_split_body_v1,
    encode_passport_link_device_body_v1, encode_passport_merge_body_v1, encode_passport_split_body_v1,
    extract_identity_receipt_schema_v1, IdentityReceiptError, MergeConflictPolicyV1, PassportLinkDeviceReceiptBodyV1,
    PassportMergeConflictV1, PassportMergeReceiptBodyV1, PassportSplitReceiptBodyV1,
    CONTENT_TYPE_PASSPORT_LINK_DEVICE_BODY_V1, CONTENT_TYPE_PASSPORT_MERGE_BODY_V1,
    CONTENT_TYPE_PASSPORT_SPLIT_BODY_V1, EVT_RECEIPT_PASSPORT_LINK_DEVICE_BODY_V1, EVT_RECEIPT_PASSPORT_MERGE_BODY_V1,
    EVT_RECEIPT_PASSPORT_SPLIT_BODY_V1, SCHEMA_PASSPORT_LINK_DEVICE_BODY_V1, SCHEMA_PASSPORT_MERGE_BODY_V1,
    SCHEMA_PASSPORT_SPLIT_BODY_V1,
};
pub use keyring_v1::{Ed25519KeyEntryV1, Ed25519KeyRingV1, KeyRingError};
pub use memory_use_v1::{
    assert_memory_use_kind_v1, build_memory_use_body_v1, extract_memory_use_entries_v1, filter_reserved_entries,
    is_reserved_entity_prefix, sign_memory_use_v1, MemoryUseBodyInputV1, MemoryUseEntryV1, MemoryUseIntentV1,
    MEMORY_USE_BODY_SCHEMA_V1, MEMORY_USE_KIND_V1, RESERVED_ENTITY_PREFIXES_V1,
};
pub use observation_envelope::{
    canonical_body_bytes, verify_observation_envelope, ObservationRecordV1, ReceiptEnvelopeV1,
};
pub use store_v1::{
    load_verification_report_v1, store_verification_report_v1, verification_report_path_v1, ReceiptStoreError,
};
pub use stream_v1::{
    assert_context_injected_kind_v1, assert_stream_end_kind_v1, build_context_injected_body_v1,
    build_stream_end_body_v1, sign_stream_v1, stream_links_injection_v1, ContextInjectedBodyInputV1,
    StreamEndBodyInputV1, StreamEndStateV1, CONTEXT_INJECTED_KIND_V1, STREAM_ABORTED_KIND_V1, STREAM_BODY_SCHEMA_V1,
    STREAM_COMPLETED_KIND_V1,
};
pub use subject_index_v1::{
    resolve_subject_receipt_id_v1, subject_index_path_v1, update_subject_index_v1, ReceiptSubjectIndexV1,
    ReceiptSubjectLatestV1, SubjectResolveModeV1,
};
pub use usage_receipt_v1::{
    assert_usage_ping_kind_v1, build_usage_ping_body_v1, sign_usage_ping_v1, UsageEventClassV1, UsagePingBodyInputV1,
    USAGE_EVENT_CLASSES_V1, USAGE_PING_ALLOWED_KEYS_V1, USAGE_PING_BODY_SCHEMA_V1, USAGE_PING_KIND_V1,
};
pub use verify_v1::{
    verify_receipt_v1, ReceiptSigV1, VerificationBindingV1, VerificationIntegrityV1, VerificationReportV1,
    VerificationSigInfoV1, VerificationTraceChecksV1, VerificationTraceSummaryV1, VerifyErrorCodeV1,
    VerifyReceiptInput,
};
pub use witness_v1::{
    assert_external_anchor_kind_v1, assert_rfc3161_timestamp_kind_v1, build_external_anchor_body_v1,
    build_rfc3161_timestamp_body_v1, is_valid_object_identifier_text_v1, parse_x509_certs_der_or_pem_v1,
    read_witnessed_proofs_jsonl, sign_external_anchor_v1, sign_rfc3161_timestamp_v1, verify_external_anchor_body_v1,
    verify_rekor_checkpoint, verify_rekor_checkpoint_p256_v1, verify_rekor_checkpoint_v1,
    verify_rfc3161_timestamp_token_binding_v1, verify_rfc3161_timestamp_token_strict_v1,
    verify_rfc6962_inclusion_proof_v1, verify_witness_binding_v1, verify_witness_proof_v1, ExternalAnchorBodyInputV1,
    Rfc3161StrictValidationOptionsV1, Rfc3161StrictValidationReportV1, Rfc3161TimestampBodyInputV1,
    WitnessLogPublicKeyV1, WitnessProofV1, EXTERNAL_ANCHOR_KIND_V1, RFC3161_TIMESTAMP_KIND_V1, WITNESS_BODY_SCHEMA_V1,
};

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
