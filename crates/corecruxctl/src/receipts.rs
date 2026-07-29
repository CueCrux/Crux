// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Receipt-tooling — sign receipts with an Ed25519 key, encode + decode CROWN bodies, base64 IO.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use corecrux_frame::{decode_canonical_header_bytes_v1, stream_hash_xxhash64};
use corecrux_receipts::{
    assert_coverage_window_kind_v1, assert_external_anchor_kind_v1, assert_rfc3161_timestamp_kind_v1,
    build_crypto_shred_destroy_marker_v1, coverage_window_chain_fold_v1, coverage_window_chain_head_hex_v1,
    coverage_window_report_canonical_json_v1, encode_cose_sign1_v1, extract_linked_receipts_v1,
    seal_crypto_shred_payload_v1, update_subject_index_v1, verify_chain_reanchor_body_v1, verify_cose_sign1,
    verify_coverage_window_body_v1, verify_external_anchor_body_v1, verify_rfc3161_timestamp_token_binding_v1,
    verify_rfc3161_timestamp_token_strict_v1, ChainReanchorBodyInputV1, CoverageAttestationBodyInputV1,
    CoverageWindowBodyInputV1, CoverageWindowCountsV1, CoverageWindowReportV1, CrownReceiptV1,
    CryptoShredDestroyMarkerInputV1, CryptoShredSealInputV1, Ed25519KeyEntryV1, Ed25519KeyRingV1,
    ExternalAnchorBodyInputV1, ReceiptSigV1, RedactionReceiptBodyInputV1, Rfc3161StrictValidationOptionsV1,
    Rfc3161StrictValidationReportV1, Rfc3161TimestampBodyInputV1, CONTENT_TYPE_RECEIPT_BODY_V1,
    CONTENT_TYPE_RECEIPT_SIG_V1, EVT_RECEIPT_BODY_V1, EVT_RECEIPT_SIG_V1, STREAM_TYPE_RECEIPT,
};
use corecrux_segment::decode_frame_v1;
use corecrux_storage::{AppendEventInput, ShardStorage, ShardStorageOptions};

type ReceiptSignerV1 = fn(&str, &[u8], [u8; 32], &SigningKey, &str, &str) -> ReceiptSigV1;

/// Deterministic throwaway signing seed used only by
/// `receipts export-cose --gen-dev-key` and the corresponding keyless
/// development verification
/// path. This is the public ResearchCrux test seed, not production key
/// material.
const COSE_DEV_SIGNING_KEY_BYTES: [u8; 32] = [
    0x0f, 0x1f, 0x4b, 0xcf, 0x72, 0xc9, 0xec, 0x25, 0x6b, 0x59, 0xb4, 0x5b, 0xdd, 0x94, 0x89, 0x09, 0x57, 0xee, 0x93,
    0x2b, 0x19, 0xc4, 0xee, 0xaa, 0x15, 0xd7, 0xd8, 0xd2, 0x96, 0xb3, 0x54, 0x7b,
];

#[derive(Debug, Clone)]
pub struct CoseExportOptionsV1<'a> {
    pub input: &'a Path,
    pub out: Option<&'a Path>,
    pub key_b64: Option<&'a str>,
    pub key_file: Option<&'a Path>,
    pub gen_dev_key: bool,
    pub issuer: &'a str,
    pub kid: &'a str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CoseExportReportV1 {
    pub input_path: String,
    pub output_path: String,
    pub snap_id: String,
    pub issuer: String,
    pub kid: String,
    pub bytes_written: usize,
    pub public_key_b64: String,
    pub development_key: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CoseVerifyReportV1 {
    pub input_path: String,
    pub snap_id: String,
    pub issuer: String,
    pub kid: String,
    pub public_key_b64: String,
    pub development_key: bool,
}

/// Read a daemon/ResearchCrux JSON receipt and export the exact CROWN SCITT
/// Application Profile v0.2 COSE_Sign1 bytes.
pub fn export_cose_file_v1(
    opts: &CoseExportOptionsV1<'_>,
) -> Result<CoseExportReportV1, Box<dyn std::error::Error + Send + Sync>> {
    let source = std::fs::read(opts.input)?;
    let source_value: serde_json::Value = serde_json::from_slice(&source)?;
    let receipt_value = source_value.get("receipt").unwrap_or(&source_value).clone();
    let receipt: CrownReceiptV1 = serde_json::from_value(receipt_value)?;
    let (signing_key, development_key) = resolve_cose_signing_key_v1(opts)?;
    let cose = encode_cose_sign1_v1(&receipt, &signing_key, opts.issuer, opts.kid.as_bytes())?;
    let output_path = opts
        .out
        .map_or_else(|| opts.input.with_extension("cose"), Path::to_path_buf);
    write_parented(&output_path, &cose)?;

    Ok(CoseExportReportV1 {
        input_path: opts.input.display().to_string(),
        output_path: output_path.display().to_string(),
        snap_id: receipt.snap_id,
        issuer: opts.issuer.to_string(),
        kid: opts.kid.to_string(),
        bytes_written: cose.len(),
        public_key_b64: base64::engine::general_purpose::STANDARD.encode(signing_key.verifying_key().as_bytes()),
        development_key,
    })
}

/// Verify a CROWN COSE_Sign1 file. Omitting `pubkey_b64` deliberately selects
/// only the fixed, documented development key; no key is trusted from the
/// statement itself.
pub fn verify_cose_file_v1(
    input: &Path,
    pubkey_b64: Option<&str>,
) -> Result<CoseVerifyReportV1, Box<dyn std::error::Error + Send + Sync>> {
    let cose = std::fs::read(input)?;
    let (verifying_key, development_key) = match pubkey_b64 {
        Some(value) => {
            let bytes = decode_fixed_32_b64("pubkey-b64", value.trim())?;
            (VerifyingKey::from_bytes(&bytes)?, false)
        }
        None => (
            SigningKey::from_bytes(&COSE_DEV_SIGNING_KEY_BYTES).verifying_key(),
            true,
        ),
    };
    let verified = verify_cose_sign1(&cose, &verifying_key)?;
    let kid = String::from_utf8(verified.protected.kid)
        .map_err(|_| "COSE protected-header kid is not valid UTF-8 as required by the CROWN profile")?;

    Ok(CoseVerifyReportV1 {
        input_path: input.display().to_string(),
        snap_id: verified.receipt.snap_id,
        issuer: verified.protected.issuer,
        kid,
        public_key_b64: base64::engine::general_purpose::STANDARD.encode(verifying_key.as_bytes()),
        development_key,
    })
}

fn resolve_cose_signing_key_v1(
    opts: &CoseExportOptionsV1<'_>,
) -> Result<(SigningKey, bool), Box<dyn std::error::Error + Send + Sync>> {
    let source_count =
        usize::from(opts.key_b64.is_some()) + usize::from(opts.key_file.is_some()) + usize::from(opts.gen_dev_key);
    if source_count != 1 {
        return Err("use exactly one of --key-b64, --key-file, or --gen-dev-key".into());
    }
    if let Some(value) = opts.key_b64 {
        let bytes = decode_fixed_32_b64("key-b64", value.trim())?;
        return Ok((SigningKey::from_bytes(&bytes), false));
    }
    if let Some(path) = opts.key_file {
        let raw = std::fs::read(path)?;
        let bytes: [u8; 32] = if raw.len() == 32 {
            raw.as_slice()
                .try_into()
                .map_err(|_| "key-file must contain a raw 32-byte Ed25519 signing seed")?
        } else {
            let text = std::str::from_utf8(&raw)
                .map_err(|_| "key-file must contain a raw 32-byte seed or its base64 encoding")?;
            decode_fixed_32_b64("key-file", text.trim())?
        };
        return Ok((SigningKey::from_bytes(&bytes), false));
    }
    Ok((SigningKey::from_bytes(&COSE_DEV_SIGNING_KEY_BYTES), true))
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReceiptsSeedReportV1 {
    pub data_dir: String,
    pub shard_id: u32,
    pub tenant_id: String,
    pub receipt_id: String,
    pub stream_hash: String,
    pub keyring_path: String,
    pub wrote_keyring: bool,
    pub outcomes: Vec<SeedOutcomeV1>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SeedOutcomeV1 {
    pub status: String,
    pub seq: u64,
    pub location: Option<SeedFrameLocationV1>,
    pub payload_hash: String,
    pub header_hash: String,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SeedFrameLocationV1 {
    pub shard_id: u64,
    pub epoch: u64,
    pub segment_seq: u64,
    pub offset: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BackfillSubjectIndexReportV1 {
    pub data_dir: String,
    pub subject_index_root: String,
    pub dry_run: bool,
    pub shards: Vec<BackfillShardReportV1>,
    pub totals: BackfillTotalsV1,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BackfillShardReportV1 {
    pub shard_id: u32,
    pub scanned_frames: u64,
    pub receipt_body_frames: u64,
    pub indexed: u64,
    pub skipped_no_subject: u64,
    pub skipped_kind_other: u64,
    pub parse_failed: u64,
}

#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct BackfillTotalsV1 {
    pub shards: u64,
    pub scanned_frames: u64,
    pub receipt_body_frames: u64,
    pub indexed: u64,
    pub skipped_no_subject: u64,
    pub skipped_kind_other: u64,
    pub parse_failed: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WitnessVerifyReportV1 {
    pub body_path: String,
    pub kind: String,
    pub ok: bool,
    pub failure_reason: Option<String>,
    pub strict_validation: Option<Rfc3161StrictValidationReportV1>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WitnessSmokeReportV1 {
    pub ok: bool,
    pub mode: &'static str,
    pub witness: WitnessProviderSmokeReportV1,
    pub tsa: TsaProviderSmokeReportV1,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WitnessProviderSmokeReportV1 {
    pub enabled: bool,
    pub provider: String,
    pub timeout_ms: u64,
    pub configured: bool,
    pub ok: bool,
    pub rekor_url: Option<String>,
    pub rekor_public_key_path: Option<String>,
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TsaProviderSmokeReportV1 {
    pub enabled: bool,
    pub configured: bool,
    pub ok: bool,
    pub tsa_url: Option<String>,
    pub tsa_root_cert_paths: Vec<String>,
    pub tsa_root_cert_sha256_fingerprints: Vec<String>,
    pub tsa_root_cert_count: usize,
    pub tsa_policy_oid: Option<String>,
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CoverageAttestReportV1 {
    pub body_path: String,
    pub sig_path: Option<String>,
    pub receipt_id: String,
    pub attestation_id: String,
    pub report_hash: String,
    pub signed: bool,
}

/// CLI report for `receipts coverage-window-attest`: the scanned counts, the
/// emitted standalone report path + hash, the signed receipt body path, and an
/// independent re-verification of the body that was just written.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CoverageWindowAttestReportV1 {
    pub tenant_id: String,
    pub from: String,
    pub to: String,
    pub events: u64,
    pub receipts: u64,
    pub anchored: u64,
    pub gaps: u64,
    pub events_without_receipt: u64,
    pub receipts_without_anchor: u64,
    pub chain_head: String,
    pub report_hash: String,
    pub report_path: String,
    pub body_path: String,
    pub sig_path: Option<String>,
    pub signed: bool,
    /// Independent structural verification of the body that was written.
    pub verified: bool,
    pub scanned_shards: u64,
    pub scanned_frames: u64,
}

#[derive(Debug, Clone)]
pub struct CoverageWindowAttestOptionsV1<'a> {
    pub data_dir: &'a Path,
    pub shard: Option<u32>,
    pub tenant_id: &'a str,
    pub from: &'a str,
    pub to: &'a str,
    pub out_report: &'a Path,
    pub out_body: &'a Path,
    pub out_sig: Option<&'a Path>,
    pub signing_key_b64: Option<&'a str>,
    pub key_id: &'a str,
    pub signed_at: &'a str,
    pub receipt_id: &'a str,
    pub attestation_id: &'a str,
    pub actor_passport: &'a str,
    pub created_at: &'a str,
    pub batch_frames: u32,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WitnessAttestReportV1 {
    pub body_path: String,
    pub sig_path: Option<String>,
    pub receipt_id: String,
    pub kind: String,
    pub verified: bool,
    pub signed: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ChainReanchorVerifyReportV1 {
    pub body_path: String,
    pub ok: bool,
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ChainReanchorAttestReportV1 {
    pub body_path: String,
    pub sig_path: Option<String>,
    pub receipt_id: String,
    pub migration_id: String,
    pub old_chain_head: String,
    pub new_chain_head: String,
    pub receipt_count: u64,
    pub linked_receipts_count: usize,
    pub verified: bool,
    pub signed: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RedactionAttestReportV1 {
    pub body_path: String,
    pub sig_path: Option<String>,
    pub envelope_path: Option<String>,
    pub receipt_id: String,
    pub redaction_id: String,
    pub subject_cek_id: String,
    pub subject_cek_commitment: String,
    pub prior_content_hash: Option<String>,
    pub redacted_content_hash: Option<String>,
    pub signed: bool,
    pub crypto_shred_staged: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CryptoShredDestroyMarkerReportV1 {
    pub marker_path: String,
    pub marker_id: String,
    pub tenant_id: String,
    pub subject_type: String,
    pub subject_id: String,
    pub subject_cek_id: String,
    pub redaction_receipt_id: String,
    pub state: String,
    pub linked_receipts_count: usize,
    pub human_gate_required: bool,
    pub destructive_action_performed: bool,
}

#[derive(Debug, Clone)]
pub struct ExternalAnchorAttestOptionsV1<'a> {
    pub out_body: &'a Path,
    pub out_sig: Option<&'a Path>,
    pub signing_key_b64: Option<&'a str>,
    pub key_id: &'a str,
    pub signed_at: &'a str,
    pub tenant_id: &'a str,
    pub receipt_id: &'a str,
    pub anchor_id: &'a str,
    pub actor_passport: &'a str,
    pub transparency_log: &'a str,
    pub log_url: &'a str,
    pub rekor_uuid: Option<&'a str>,
    pub leaf_hash: &'a str,
    pub log_index: u64,
    pub tree_size: u64,
    pub root_hash: &'a str,
    pub inclusion_proof: &'a [&'a str],
    pub checkpoint: Option<&'a str>,
    pub integrated_time: &'a str,
    pub created_at: &'a str,
}

#[derive(Debug, Clone)]
pub struct Rfc3161TimestampAttestOptionsV1<'a> {
    pub out_body: &'a Path,
    pub out_sig: Option<&'a Path>,
    pub signing_key_b64: Option<&'a str>,
    pub key_id: &'a str,
    pub signed_at: &'a str,
    pub tenant_id: &'a str,
    pub receipt_id: &'a str,
    pub timestamp_id: &'a str,
    pub actor_passport: &'a str,
    pub tsa_url: &'a str,
    pub tsa_policy_oid: Option<&'a str>,
    pub message_imprint_alg: &'a str,
    pub message_imprint_hash: &'a str,
    pub timestamp_token_der: &'a Path,
    pub serial_number: Option<&'a str>,
    pub gen_time: &'a str,
    pub created_at: &'a str,
}

#[derive(Debug, Clone)]
pub struct Rfc3161TimestampVerifyOptionsV1<'a> {
    pub expected_message_imprint_hash: Option<&'a str>,
    pub expected_policy_oid: Option<&'a str>,
    pub expected_nonce: Option<&'a [u8]>,
    pub trusted_root_cert_paths: &'a [PathBuf],
}

#[derive(Debug, Clone)]
pub struct WitnessSmokeOptionsV1<'a> {
    pub witness_enabled: bool,
    pub witness_provider: &'a str,
    pub witness_timeout_ms: u64,
    pub rekor_url: Option<&'a str>,
    pub rekor_public_key_path: Option<&'a Path>,
    pub tsa_enabled: bool,
    pub tsa_url: Option<&'a str>,
    pub tsa_root_cert_paths: &'a [PathBuf],
    pub tsa_policy_oid: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct ChainReanchorAttestOptionsV1<'a> {
    pub out_body: &'a Path,
    pub out_sig: Option<&'a Path>,
    pub signing_key_b64: Option<&'a str>,
    pub key_id: &'a str,
    pub signed_at: &'a str,
    pub tenant_id: &'a str,
    pub receipt_id: &'a str,
    pub migration_id: &'a str,
    pub actor_passport: &'a str,
    pub old_chain_head: &'a str,
    pub new_chain_head: &'a str,
    pub old_hash_alg: &'a str,
    pub new_hash_alg: &'a str,
    pub first_receipt_id: &'a str,
    pub last_receipt_id: &'a str,
    pub receipt_count: u64,
    pub reason: &'a str,
    pub linked_receipts: &'a [&'a str],
    pub created_at: &'a str,
}

#[derive(Debug, Clone)]
pub struct RedactionAttestOptionsV1<'a> {
    pub out_body: &'a Path,
    pub out_sig: Option<&'a Path>,
    pub signing_key_b64: Option<&'a str>,
    pub key_id: &'a str,
    pub signed_at: &'a str,
    pub tenant_id: &'a str,
    pub receipt_id: &'a str,
    pub redaction_id: &'a str,
    pub actor_passport: &'a str,
    pub subject_type: &'a str,
    pub subject_id: &'a str,
    pub request_id: &'a str,
    pub scope: &'a str,
    pub method: &'a str,
    pub subject_cek_id: &'a str,
    pub subject_cek_commitment: Option<&'a str>,
    pub cek_destroyed_at: Option<&'a str>,
    pub prior_content_hash: Option<&'a str>,
    pub redacted_content_hash: Option<&'a str>,
    pub linked_receipts: &'a [&'a str],
    pub created_at: &'a str,
    pub crypto_shred_staged: bool,
    pub seal_plaintext: Option<&'a Path>,
    pub out_envelope: Option<&'a Path>,
    pub cek_b64: Option<&'a str>,
    pub nonce_b64: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct CryptoShredDestroyMarkerOptionsV1<'a> {
    pub out_marker: &'a Path,
    pub marker_id: &'a str,
    pub tenant_id: &'a str,
    pub subject_type: &'a str,
    pub subject_id: &'a str,
    pub subject_cek_id: &'a str,
    pub subject_cek_commitment: &'a str,
    pub redaction_receipt_id: &'a str,
    pub actor_passport: &'a str,
    pub idempotency_key: &'a str,
    pub requested_at: &'a str,
    pub destroyed_at: Option<&'a str>,
    pub human_gate_receipt: Option<&'a str>,
    pub wrapped_key_ref: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub linked_receipts: &'a [&'a str],
}

pub fn write_external_anchor_attestation_v1(
    opts: &ExternalAnchorAttestOptionsV1<'_>,
) -> Result<WitnessAttestReportV1, Box<dyn std::error::Error + Send + Sync>> {
    let input = ExternalAnchorBodyInputV1 {
        tenant_id: opts.tenant_id,
        receipt_id: opts.receipt_id,
        anchor_id: opts.anchor_id,
        actor_passport: opts.actor_passport,
        transparency_log: opts.transparency_log,
        log_url: opts.log_url,
        rekor_uuid: opts.rekor_uuid,
        leaf_hash: opts.leaf_hash,
        log_index: opts.log_index,
        tree_size: opts.tree_size,
        root_hash: opts.root_hash,
        inclusion_proof: opts.inclusion_proof,
        checkpoint: opts.checkpoint,
        integrated_time: opts.integrated_time,
        created_at: opts.created_at,
    };
    let (body, body_hash) = corecrux_receipts::build_external_anchor_body_v1(&input);
    let verified = verify_external_anchor_body_v1(&body);
    if !verified {
        return Err("external_anchor body failed inclusion-proof verification".into());
    }
    write_parented(opts.out_body, &body)?;
    let sig_path = write_optional_sig_v1(OptionalSigWriteV1 {
        out_sig: opts.out_sig,
        signing_key_b64: opts.signing_key_b64,
        receipt_id: opts.receipt_id,
        body: &body,
        body_hash,
        key_id: opts.key_id,
        signed_at: opts.signed_at,
        signer: corecrux_receipts::sign_external_anchor_v1,
    })?;
    Ok(WitnessAttestReportV1 {
        body_path: opts.out_body.display().to_string(),
        sig_path,
        receipt_id: opts.receipt_id.to_string(),
        kind: "external_anchor".to_string(),
        verified,
        signed: opts.out_sig.is_some(),
    })
}

pub fn write_rfc3161_timestamp_attestation_v1(
    opts: &Rfc3161TimestampAttestOptionsV1<'_>,
) -> Result<WitnessAttestReportV1, Box<dyn std::error::Error + Send + Sync>> {
    let token = std::fs::read(opts.timestamp_token_der)?;
    let input = Rfc3161TimestampBodyInputV1 {
        tenant_id: opts.tenant_id,
        receipt_id: opts.receipt_id,
        timestamp_id: opts.timestamp_id,
        actor_passport: opts.actor_passport,
        tsa_url: opts.tsa_url,
        tsa_policy_oid: opts.tsa_policy_oid,
        message_imprint_alg: opts.message_imprint_alg,
        message_imprint_hash: opts.message_imprint_hash,
        timestamp_token_der: &token,
        serial_number: opts.serial_number,
        gen_time: opts.gen_time,
        created_at: opts.created_at,
    };
    let (body, body_hash) = corecrux_receipts::build_rfc3161_timestamp_body_v1(&input);
    let verified = verify_rfc3161_timestamp_token_binding_v1(&body, Some(opts.message_imprint_hash));
    if !verified {
        return Err("rfc3161_timestamp body failed token/imprint binding verification".into());
    }
    write_parented(opts.out_body, &body)?;
    let sig_path = write_optional_sig_v1(OptionalSigWriteV1 {
        out_sig: opts.out_sig,
        signing_key_b64: opts.signing_key_b64,
        receipt_id: opts.receipt_id,
        body: &body,
        body_hash,
        key_id: opts.key_id,
        signed_at: opts.signed_at,
        signer: corecrux_receipts::sign_rfc3161_timestamp_v1,
    })?;
    Ok(WitnessAttestReportV1 {
        body_path: opts.out_body.display().to_string(),
        sig_path,
        receipt_id: opts.receipt_id.to_string(),
        kind: "rfc3161_timestamp".to_string(),
        verified,
        signed: opts.out_sig.is_some(),
    })
}

struct OptionalSigWriteV1<'a> {
    out_sig: Option<&'a Path>,
    signing_key_b64: Option<&'a str>,
    receipt_id: &'a str,
    body: &'a [u8],
    body_hash: [u8; 32],
    key_id: &'a str,
    signed_at: &'a str,
    signer: ReceiptSignerV1,
}

fn write_optional_sig_v1(
    opts: OptionalSigWriteV1<'_>,
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    let Some(sig_path) = opts.out_sig else {
        return Ok(None);
    };
    let signing_key_b64 = opts
        .signing_key_b64
        .ok_or("signing-key-b64 is required when out-sig is set")?;
    let key_bytes = decode_fixed_32_b64("signing-key-b64", signing_key_b64)?;
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let sig = (opts.signer)(
        opts.receipt_id,
        opts.body,
        opts.body_hash,
        &signing_key,
        opts.key_id,
        opts.signed_at,
    );
    let mut sig_bytes = Vec::new();
    ciborium::ser::into_writer(&sig, &mut sig_bytes)?;
    write_parented(sig_path, &sig_bytes)?;
    Ok(Some(sig_path.display().to_string()))
}

pub fn write_chain_reanchor_attestation_v1(
    opts: &ChainReanchorAttestOptionsV1<'_>,
) -> Result<ChainReanchorAttestReportV1, Box<dyn std::error::Error + Send + Sync>> {
    let input = ChainReanchorBodyInputV1 {
        tenant_id: opts.tenant_id,
        receipt_id: opts.receipt_id,
        migration_id: opts.migration_id,
        actor_passport: opts.actor_passport,
        old_chain_head: opts.old_chain_head,
        new_chain_head: opts.new_chain_head,
        old_hash_alg: opts.old_hash_alg,
        new_hash_alg: opts.new_hash_alg,
        first_receipt_id: opts.first_receipt_id,
        last_receipt_id: opts.last_receipt_id,
        receipt_count: opts.receipt_count,
        reason: opts.reason,
        linked_receipts: opts.linked_receipts,
        created_at: opts.created_at,
    };
    let (body, body_hash) = corecrux_receipts::build_chain_reanchor_body_v1(&input);
    let verified = verify_chain_reanchor_body_v1(&body);
    if !verified {
        return Err("chain_reanchor body failed structural verification".into());
    }
    write_parented(opts.out_body, &body)?;

    let mut sig_path_out = None;
    if let Some(sig_path) = opts.out_sig {
        let signing_key_b64 = opts
            .signing_key_b64
            .ok_or("signing-key-b64 is required when out-sig is set")?;
        let key_bytes = decode_fixed_32_b64("signing-key-b64", signing_key_b64)?;
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let sig = corecrux_receipts::sign_chain_reanchor_v1(
            opts.receipt_id,
            &body,
            body_hash,
            &signing_key,
            opts.key_id,
            opts.signed_at,
        );
        let mut sig_bytes = Vec::new();
        ciborium::ser::into_writer(&sig, &mut sig_bytes)?;
        write_parented(sig_path, &sig_bytes)?;
        sig_path_out = Some(sig_path.display().to_string());
    }

    Ok(ChainReanchorAttestReportV1 {
        body_path: opts.out_body.display().to_string(),
        sig_path: sig_path_out,
        receipt_id: opts.receipt_id.to_string(),
        migration_id: opts.migration_id.to_string(),
        old_chain_head: opts.old_chain_head.to_string(),
        new_chain_head: opts.new_chain_head.to_string(),
        receipt_count: opts.receipt_count,
        linked_receipts_count: opts.linked_receipts.len(),
        verified,
        signed: opts.out_sig.is_some(),
    })
}

pub fn verify_chain_reanchor_body_file_v1(
    body_path: &Path,
) -> Result<ChainReanchorVerifyReportV1, Box<dyn std::error::Error + Send + Sync>> {
    let body = std::fs::read(body_path)?;
    let ok = verify_chain_reanchor_body_v1(&body);
    Ok(ChainReanchorVerifyReportV1 {
        body_path: body_path.display().to_string(),
        ok,
        failure_reason: if ok {
            None
        } else {
            Some(
                "body is not a structurally valid chain_reanchor receipt body; check kind, heads, algorithms, receipt_count, and linked_receipts"
                    .to_string(),
            )
        },
    })
}

pub fn write_redaction_attestation_v1(
    opts: &RedactionAttestOptionsV1<'_>,
) -> Result<RedactionAttestReportV1, Box<dyn std::error::Error + Send + Sync>> {
    let mut envelope_path_out = None;
    let mut derived_subject_cek_commitment = opts.subject_cek_commitment.map(str::to_string);
    let mut derived_prior_content_hash = opts.prior_content_hash.map(str::to_string);
    let mut derived_redacted_content_hash = opts.redacted_content_hash.map(str::to_string);

    if opts.crypto_shred_staged {
        let seal_plaintext = opts
            .seal_plaintext
            .ok_or("--seal-plaintext is required with --crypto-shred-staged")?;
        let out_envelope = opts
            .out_envelope
            .ok_or("--out-envelope is required with --crypto-shred-staged")?;
        let cek_b64 = opts.cek_b64.ok_or("--cek-b64 is required with --crypto-shred-staged")?;
        let nonce_b64 = opts
            .nonce_b64
            .ok_or("--nonce-b64 is required with --crypto-shred-staged")?;
        let cek = decode_fixed_32_b64("cek-b64", cek_b64)?;
        let nonce = decode_fixed_24_b64("nonce-b64", nonce_b64)?;
        let plaintext = std::fs::read(seal_plaintext)?;
        let seal_input = CryptoShredSealInputV1 {
            tenant_id: opts.tenant_id,
            subject_type: opts.subject_type,
            subject_id: opts.subject_id,
            subject_cek_id: opts.subject_cek_id,
            created_at: opts.created_at,
        };
        let envelope = seal_crypto_shred_payload_v1(&seal_input, &plaintext, &cek, &nonce)?;
        derived_subject_cek_commitment = Some(envelope.subject_cek_commitment.clone());
        derived_prior_content_hash.get_or_insert_with(|| envelope.plaintext_hash.clone());
        derived_redacted_content_hash.get_or_insert_with(|| envelope.ciphertext_hash.clone());
        let envelope_bytes = serde_json::to_vec_pretty(&envelope)?;
        write_parented(out_envelope, &envelope_bytes)?;
        envelope_path_out = Some(out_envelope.display().to_string());
    } else if opts.seal_plaintext.is_some()
        || opts.out_envelope.is_some()
        || opts.cek_b64.is_some()
        || opts.nonce_b64.is_some()
    {
        return Err("envelope options require --crypto-shred-staged".into());
    }

    let subject_cek_commitment = derived_subject_cek_commitment
        .as_deref()
        .ok_or("--subject-cek-commitment is required unless --crypto-shred-staged derives it")?;
    let input = RedactionReceiptBodyInputV1 {
        tenant_id: opts.tenant_id,
        receipt_id: opts.receipt_id,
        redaction_id: opts.redaction_id,
        actor_passport: opts.actor_passport,
        subject_type: opts.subject_type,
        subject_id: opts.subject_id,
        request_id: opts.request_id,
        scope: opts.scope,
        method: opts.method,
        subject_cek_id: opts.subject_cek_id,
        subject_cek_commitment,
        cek_destroyed_at: opts.cek_destroyed_at,
        prior_content_hash: derived_prior_content_hash.as_deref(),
        redacted_content_hash: derived_redacted_content_hash.as_deref(),
        linked_receipts: opts.linked_receipts,
        created_at: opts.created_at,
    };
    let (body, body_hash) = corecrux_receipts::build_redaction_receipt_body_v1(&input);
    write_parented(opts.out_body, &body)?;

    let mut sig_path_out = None;
    if let Some(sig_path) = opts.out_sig {
        let signing_key_b64 = opts
            .signing_key_b64
            .ok_or("signing-key-b64 is required when out-sig is set")?;
        let key_bytes = decode_fixed_32_b64("signing-key-b64", signing_key_b64)?;
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let sig = corecrux_receipts::sign_redaction_receipt_v1(
            opts.receipt_id,
            &body,
            body_hash,
            &signing_key,
            opts.key_id,
            opts.signed_at,
        );
        let mut sig_bytes = Vec::new();
        ciborium::ser::into_writer(&sig, &mut sig_bytes)?;
        write_parented(sig_path, &sig_bytes)?;
        sig_path_out = Some(sig_path.display().to_string());
    }

    Ok(RedactionAttestReportV1 {
        body_path: opts.out_body.display().to_string(),
        sig_path: sig_path_out,
        envelope_path: envelope_path_out,
        receipt_id: opts.receipt_id.to_string(),
        redaction_id: opts.redaction_id.to_string(),
        subject_cek_id: opts.subject_cek_id.to_string(),
        subject_cek_commitment: subject_cek_commitment.to_string(),
        prior_content_hash: derived_prior_content_hash,
        redacted_content_hash: derived_redacted_content_hash,
        signed: opts.out_sig.is_some(),
        crypto_shred_staged: opts.crypto_shred_staged,
    })
}

pub fn write_crypto_shred_destroy_marker_v1(
    opts: &CryptoShredDestroyMarkerOptionsV1<'_>,
) -> Result<CryptoShredDestroyMarkerReportV1, Box<dyn std::error::Error + Send + Sync>> {
    let marker = build_crypto_shred_destroy_marker_v1(&CryptoShredDestroyMarkerInputV1 {
        marker_id: opts.marker_id,
        tenant_id: opts.tenant_id,
        subject_type: opts.subject_type,
        subject_id: opts.subject_id,
        subject_cek_id: opts.subject_cek_id,
        subject_cek_commitment: opts.subject_cek_commitment,
        redaction_receipt_id: opts.redaction_receipt_id,
        actor_passport: opts.actor_passport,
        idempotency_key: opts.idempotency_key,
        requested_at: opts.requested_at,
        destroyed_at: opts.destroyed_at,
        human_gate_receipt: opts.human_gate_receipt,
        wrapped_key_ref: opts.wrapped_key_ref,
        reason: opts.reason,
        linked_receipts: opts.linked_receipts,
    })?;
    let marker_bytes = serde_json::to_vec_pretty(&marker)?;
    write_parented(opts.out_marker, &marker_bytes)?;

    Ok(CryptoShredDestroyMarkerReportV1 {
        marker_path: opts.out_marker.display().to_string(),
        marker_id: marker.marker_id,
        tenant_id: marker.tenant_id,
        subject_type: marker.subject_type,
        subject_id: marker.subject_id,
        subject_cek_id: marker.subject_cek_id,
        redaction_receipt_id: marker.redaction_receipt_id,
        state: marker.state,
        linked_receipts_count: marker.linked_receipts.len(),
        human_gate_required: marker.destroyed_at.is_none(),
        destructive_action_performed: false,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn write_coverage_attestation_v1(
    out_body: &Path,
    out_sig: Option<&Path>,
    signing_key_b64: Option<&str>,
    key_id: &str,
    signed_at: &str,
    tenant_id: &str,
    receipt_id: &str,
    attestation_id: &str,
    actor_passport: &str,
    subject: &str,
    corpus: &str,
    run_id: &str,
    commit_sha: &str,
    lane_flags: &str,
    metric: &str,
    score: f64,
    floor: Option<f64>,
    below_floor: u64,
    capability_count: Option<u64>,
    covered_count: Option<u64>,
    gaps_hash: Option<&str>,
    report_path: &Path,
    created_at: &str,
) -> Result<CoverageAttestReportV1, Box<dyn std::error::Error + Send + Sync>> {
    let report_bytes = std::fs::read(report_path)?;
    let report_hash = format!("blake3:{}", hex32(blake3::hash(&report_bytes).as_bytes()));
    let input = CoverageAttestationBodyInputV1 {
        tenant_id,
        receipt_id,
        attestation_id,
        actor_passport,
        subject,
        corpus,
        run_id,
        commit_sha,
        lane_flags,
        metric,
        score,
        floor,
        below_floor,
        capability_count,
        covered_count,
        gaps_hash,
        report_hash: &report_hash,
        created_at,
    };
    let (body, body_hash) = corecrux_receipts::build_coverage_attestation_body_v1(&input);
    write_parented(out_body, &body)?;

    let mut sig_path_out = None;
    if let Some(sig_path) = out_sig {
        let signing_key_b64 = signing_key_b64.ok_or("signing-key-b64 is required when out-sig is set")?;
        let key_bytes = base64::engine::general_purpose::STANDARD.decode(signing_key_b64)?;
        let key_bytes: [u8; 32] = key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "signing-key-b64 must decode to a 32-byte Ed25519 signing key")?;
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let sig = corecrux_receipts::sign_coverage_attestation_v1(
            receipt_id,
            &body,
            body_hash,
            &signing_key,
            key_id,
            signed_at,
        );
        let mut sig_bytes = Vec::new();
        ciborium::ser::into_writer(&sig, &mut sig_bytes)?;
        write_parented(sig_path, &sig_bytes)?;
        sig_path_out = Some(sig_path.display().to_string());
    }

    Ok(CoverageAttestReportV1 {
        body_path: out_body.display().to_string(),
        sig_path: sig_path_out,
        receipt_id: receipt_id.to_string(),
        attestation_id: attestation_id.to_string(),
        report_hash,
        signed: out_sig.is_some(),
    })
}

/// Read a receipt id from a receipt-body CBOR map (top-level `receipt_id`).
fn body_receipt_id_v1(body_bytes: &[u8]) -> Option<String> {
    let v: ciborium::value::Value = ciborium::de::from_reader(std::io::Cursor::new(body_bytes)).ok()?;
    let ciborium::value::Value::Map(map) = v else {
        return None;
    };
    for (k, val) in &map {
        if let (ciborium::value::Value::Text(k), ciborium::value::Value::Text(s)) = (k, val) {
            if k == "receipt_id" {
                return Some(s.clone());
            }
        }
    }
    None
}

/// True if `ts` (RFC3339) falls in `[from, to)`. Falls back to lexical string
/// comparison when a bound fails to parse — RFC3339 UTC timestamps are
/// lexically ordered, and our producers emit `...Z`, so this is sound for the
/// common case while never panicking on malformed input.
fn ts_in_window(ts: &str, from: &str, to: &str) -> bool {
    use chrono::DateTime;
    match (
        DateTime::parse_from_rfc3339(ts),
        DateTime::parse_from_rfc3339(from),
        DateTime::parse_from_rfc3339(to),
    ) {
        (Ok(t), Ok(f), Ok(u)) => t >= f && t < u,
        _ => ts >= from && ts < to,
    }
}

/// Scan a tenant's store over `[from, to)`, count events / receipts / anchored
/// receipts, compute gaps, fold a deterministic chain head, then write a
/// standalone canonical-JSON report and a signed `coverage_window` receipt
/// body. The written body is re-verified independently before returning.
pub fn coverage_window_attest_v1(
    opts: &CoverageWindowAttestOptionsV1<'_>,
) -> Result<CoverageWindowAttestReportV1, Box<dyn std::error::Error + Send + Sync>> {
    let shard_root = opts.data_dir.join("shards");
    if !shard_root.exists() {
        return Err(format!("shard root not found: {}", shard_root.display()).into());
    }
    let shard_ids = if let Some(id) = opts.shard {
        vec![id]
    } else {
        list_shards(&shard_root)?
    };

    let mut events = 0u64;
    let mut receipts = 0u64;
    let mut scanned_frames = 0u64;
    let mut scanned_shards = 0u64;
    let mut chain_head = [0u8; 32];
    // Receipt ids that are anchor receipts themselves OR are linked from an anchor.
    let mut anchor_receipt_ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    // Receipt ids of plain (non-anchor) receipt bodies seen in the window.
    let mut receipt_ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for shard_id in shard_ids {
        let storage = ShardStorage::open(&shard_root, shard_id, /*epoch=*/ 1, ShardStorageOptions::default())?;
        scanned_shards += 1;

        let mut cursor: Option<corecrux_storage::ReplayCursor> = None;
        loop {
            let (frames, next) = storage.replay_from(cursor, opts.batch_frames)?;
            if frames.is_empty() {
                break;
            }
            for (_loc, frame_bytes) in frames {
                let frame = match decode_frame_v1(&frame_bytes) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let hdr = match decode_canonical_header_bytes_v1(&frame.header_bytes) {
                    Ok(h) => h,
                    Err(_) => continue,
                };
                if hdr.tenant_id != opts.tenant_id {
                    continue;
                }
                if !ts_in_window(&hdr.ingested_at, opts.from, opts.to) {
                    continue;
                }
                scanned_frames += 1;
                // Fold every in-window frame's payload hash into the chain head,
                // in deterministic replay order.
                let ph = corecrux_frame::compute_payload_hash(&frame.payload_bytes);
                chain_head = coverage_window_chain_fold_v1(chain_head, &ph);

                let is_receipt_body = hdr.stream_type == STREAM_TYPE_RECEIPT && hdr.event_type == EVT_RECEIPT_BODY_V1;
                if !is_receipt_body {
                    // Receipt sig frames are bookkeeping, not first-class events;
                    // everything else in-window is an event that should be covered.
                    if !(hdr.stream_type == STREAM_TYPE_RECEIPT && hdr.event_type == EVT_RECEIPT_SIG_V1) {
                        events += 1;
                    }
                    continue;
                }

                receipts += 1;
                let payload = &frame.payload_bytes;
                let is_anchor = assert_external_anchor_kind_v1(payload) || assert_rfc3161_timestamp_kind_v1(payload);
                if let Some(rid) = body_receipt_id_v1(payload) {
                    if is_anchor {
                        anchor_receipt_ids.insert(rid);
                    } else {
                        receipt_ids.insert(rid);
                    }
                }
                if is_anchor {
                    // An anchor's linked_receipts are the receipt ids it anchors.
                    if let Some(linked) = extract_linked_receipts_v1(payload) {
                        for r in linked {
                            anchor_receipt_ids.insert(r);
                        }
                    }
                }
            }
            cursor = next;
            if cursor.is_none() {
                break;
            }
        }
    }

    // A receipt body counts as "anchored" if it is an anchor receipt itself or
    // is referenced by an anchor's linked_receipts. The deduped id set may name
    // anchor targets that fell outside the window, so clamp to `receipts` (the
    // verify step enforces `anchored <= receipts`).
    let _ = &receipt_ids; // distinct-id population is informational only.
    let anchored = receipts.min(anchor_receipt_ids.len() as u64);
    let receipts_without_anchor = receipts.saturating_sub(anchored);
    let events_without_receipt = events.saturating_sub(receipts);
    let counts = CoverageWindowCountsV1 {
        events,
        receipts,
        anchored,
        events_without_receipt,
        receipts_without_anchor,
    };

    let chain_head_hex = coverage_window_chain_head_hex_v1(chain_head);
    let report = CoverageWindowReportV1::new(opts.tenant_id, opts.from, opts.to, counts, &chain_head_hex);
    let report_hash = report.report_hash();
    let report_bytes = coverage_window_report_canonical_json_v1(&report);
    write_parented(opts.out_report, &report_bytes)?;

    let input = CoverageWindowBodyInputV1 {
        tenant_id: opts.tenant_id,
        receipt_id: opts.receipt_id,
        attestation_id: opts.attestation_id,
        actor_passport: opts.actor_passport,
        from: opts.from,
        to: opts.to,
        events,
        receipts,
        anchored,
        gaps: counts.gaps(),
        events_without_receipt,
        receipts_without_anchor,
        chain_head: &chain_head_hex,
        report_hash: &report_hash,
        created_at: opts.created_at,
    };
    let (body, body_hash) = corecrux_receipts::build_coverage_window_body_v1(&input);
    let verified = verify_coverage_window_body_v1(&body) && assert_coverage_window_kind_v1(&body);
    if !verified {
        return Err("coverage_window body failed structural verification".into());
    }
    write_parented(opts.out_body, &body)?;

    let sig_path = write_optional_sig_v1(OptionalSigWriteV1 {
        out_sig: opts.out_sig,
        signing_key_b64: opts.signing_key_b64,
        receipt_id: opts.receipt_id,
        body: &body,
        body_hash,
        key_id: opts.key_id,
        signed_at: opts.signed_at,
        signer: corecrux_receipts::sign_coverage_window_v1,
    })?;

    Ok(CoverageWindowAttestReportV1 {
        tenant_id: opts.tenant_id.to_string(),
        from: opts.from.to_string(),
        to: opts.to.to_string(),
        events,
        receipts,
        anchored,
        gaps: counts.gaps(),
        events_without_receipt,
        receipts_without_anchor,
        chain_head: chain_head_hex,
        report_hash,
        report_path: opts.out_report.display().to_string(),
        body_path: opts.out_body.display().to_string(),
        sig_path,
        signed: opts.out_sig.is_some(),
        verified,
        scanned_shards,
        scanned_frames,
    })
}

pub fn verify_external_anchor_body_file_v1(
    body_path: &Path,
) -> Result<WitnessVerifyReportV1, Box<dyn std::error::Error + Send + Sync>> {
    let body = std::fs::read(body_path)?;
    let kind_ok = assert_external_anchor_kind_v1(&body);
    let proof_ok = kind_ok && verify_external_anchor_body_v1(&body);
    Ok(WitnessVerifyReportV1 {
        body_path: body_path.display().to_string(),
        kind: "external_anchor".to_string(),
        ok: proof_ok,
        failure_reason: if proof_ok {
            None
        } else if kind_ok {
            Some("RFC6962 inclusion proof does not match leaf/root/tree metadata".to_string())
        } else {
            Some("body is not an external_anchor receipt body".to_string())
        },
        strict_validation: None,
    })
}

pub fn verify_rfc3161_timestamp_body_file_v1(
    body_path: &Path,
    expected_message_imprint_hash: Option<&str>,
) -> Result<WitnessVerifyReportV1, Box<dyn std::error::Error + Send + Sync>> {
    let trusted_root_cert_paths = Vec::new();
    verify_rfc3161_timestamp_body_file_with_options_v1(
        body_path,
        &Rfc3161TimestampVerifyOptionsV1 {
            expected_message_imprint_hash,
            expected_policy_oid: None,
            expected_nonce: None,
            trusted_root_cert_paths: &trusted_root_cert_paths,
        },
    )
}

pub fn verify_rfc3161_timestamp_body_file_with_options_v1(
    body_path: &Path,
    opts: &Rfc3161TimestampVerifyOptionsV1<'_>,
) -> Result<WitnessVerifyReportV1, Box<dyn std::error::Error + Send + Sync>> {
    let body = std::fs::read(body_path)?;
    let kind_ok = assert_rfc3161_timestamp_kind_v1(&body);
    let binding_ok = kind_ok && verify_rfc3161_timestamp_token_binding_v1(&body, opts.expected_message_imprint_hash);

    let mut trusted_root_certs_der = Vec::new();
    for path in opts.trusted_root_cert_paths {
        let cert_bytes = std::fs::read(path)?;
        let mut certs = corecrux_receipts::parse_x509_certs_der_or_pem_v1(&cert_bytes)
            .map_err(|err| format!("failed to parse trusted TSA root {}: {err}", path.display()))?;
        trusted_root_certs_der.append(&mut certs);
    }
    let trusted_root_refs = trusted_root_certs_der.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let strict_validation = if trusted_root_refs.is_empty() {
        None
    } else {
        Some(verify_rfc3161_timestamp_token_strict_v1(
            &body,
            &Rfc3161StrictValidationOptionsV1 {
                expected_message_imprint_hash: opts.expected_message_imprint_hash,
                expected_policy_oid: opts.expected_policy_oid,
                expected_nonce: opts.expected_nonce,
                trusted_root_certs_der: &trusted_root_refs,
            },
        ))
    };
    let ok = strict_validation.as_ref().map_or(binding_ok, |report| report.ok);
    Ok(WitnessVerifyReportV1 {
        body_path: body_path.display().to_string(),
        kind: "rfc3161_timestamp".to_string(),
        ok,
        failure_reason: if ok {
            None
        } else if let Some(report) = &strict_validation {
            report.failure_reason.clone()
        } else if kind_ok {
            Some("timestamp token hash or expected message imprint binding mismatch".to_string())
        } else {
            Some("body is not an rfc3161_timestamp receipt body".to_string())
        },
        strict_validation,
    })
}

pub fn witness_smoke_v1(opts: &WitnessSmokeOptionsV1<'_>) -> WitnessSmokeReportV1 {
    let mut warnings = Vec::new();
    let witness = witness_provider_smoke_v1(opts, &mut warnings);
    let tsa = tsa_provider_smoke_v1(opts, &mut warnings);
    WitnessSmokeReportV1 {
        ok: witness.ok && tsa.ok,
        mode: "local_config_only",
        witness,
        tsa,
        warnings,
    }
}

fn witness_provider_smoke_v1(
    opts: &WitnessSmokeOptionsV1<'_>,
    warnings: &mut Vec<String>,
) -> WitnessProviderSmokeReportV1 {
    if !opts.witness_enabled {
        return WitnessProviderSmokeReportV1 {
            enabled: false,
            provider: opts.witness_provider.to_string(),
            timeout_ms: opts.witness_timeout_ms,
            configured: false,
            ok: true,
            rekor_url: opts.rekor_url.map(str::to_string),
            rekor_public_key_path: opts.rekor_public_key_path.map(|p| p.display().to_string()),
            failure_reason: None,
        };
    }

    if opts.witness_timeout_ms == 0 {
        return WitnessProviderSmokeReportV1 {
            enabled: true,
            provider: opts.witness_provider.to_string(),
            timeout_ms: opts.witness_timeout_ms,
            configured: false,
            ok: false,
            rekor_url: opts.rekor_url.map(str::to_string),
            rekor_public_key_path: opts.rekor_public_key_path.map(|p| p.display().to_string()),
            failure_reason: Some("--witness-timeout-ms must be greater than zero".to_string()),
        };
    }

    if !opts.witness_provider.trim().eq_ignore_ascii_case("rekor") {
        return WitnessProviderSmokeReportV1 {
            enabled: true,
            provider: opts.witness_provider.to_string(),
            timeout_ms: opts.witness_timeout_ms,
            configured: false,
            ok: false,
            rekor_url: opts.rekor_url.map(str::to_string),
            rekor_public_key_path: opts.rekor_public_key_path.map(|p| p.display().to_string()),
            failure_reason: Some(format!("unsupported witness provider: {}", opts.witness_provider)),
        };
    }
    if opts.rekor_url.is_none_or(str::is_empty) {
        return WitnessProviderSmokeReportV1 {
            enabled: true,
            provider: opts.witness_provider.to_string(),
            timeout_ms: opts.witness_timeout_ms,
            configured: false,
            ok: false,
            rekor_url: opts.rekor_url.map(str::to_string),
            rekor_public_key_path: opts.rekor_public_key_path.map(|p| p.display().to_string()),
            failure_reason: Some("--rekor-url is required when --witness-enabled is set".to_string()),
        };
    }
    if opts.rekor_url.is_some_and(|url| !looks_https_url(url)) {
        warnings.push("Rekor witness URL is not HTTPS; use only for local/non-prod mocks".to_string());
    }
    if let Some(path) = opts.rekor_public_key_path {
        if !path.is_file() {
            return WitnessProviderSmokeReportV1 {
                enabled: true,
                provider: opts.witness_provider.to_string(),
                timeout_ms: opts.witness_timeout_ms,
                configured: false,
                ok: false,
                rekor_url: opts.rekor_url.map(str::to_string),
                rekor_public_key_path: Some(path.display().to_string()),
                failure_reason: Some(format!("Rekor public key path is not readable: {}", path.display())),
            };
        }
    } else {
        warnings.push("Rekor witness is enabled without --rekor-public-key-path".to_string());
    }

    WitnessProviderSmokeReportV1 {
        enabled: true,
        provider: opts.witness_provider.to_string(),
        timeout_ms: opts.witness_timeout_ms,
        configured: true,
        ok: true,
        rekor_url: opts.rekor_url.map(str::to_string),
        rekor_public_key_path: opts.rekor_public_key_path.map(|p| p.display().to_string()),
        failure_reason: None,
    }
}

fn tsa_provider_smoke_v1(opts: &WitnessSmokeOptionsV1<'_>, warnings: &mut Vec<String>) -> TsaProviderSmokeReportV1 {
    let root_paths = opts
        .tsa_root_cert_paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>();
    if !opts.tsa_enabled {
        return TsaProviderSmokeReportV1 {
            enabled: false,
            configured: false,
            ok: true,
            tsa_url: opts.tsa_url.map(str::to_string),
            tsa_root_cert_paths: root_paths,
            tsa_root_cert_sha256_fingerprints: Vec::new(),
            tsa_root_cert_count: 0,
            tsa_policy_oid: opts.tsa_policy_oid.map(str::to_string),
            failure_reason: None,
        };
    }
    if opts.tsa_url.is_none_or(str::is_empty) {
        return tsa_smoke_fail_v1(
            opts,
            root_paths,
            Vec::new(),
            0,
            "--tsa-url is required when --tsa-enabled is set",
        );
    }
    if opts.tsa_url.is_some_and(|url| !looks_https_url(url)) {
        warnings.push("TSA URL is not HTTPS; use only for local/non-prod mocks".to_string());
    }
    if let Some(policy_oid) = opts.tsa_policy_oid {
        if !corecrux_receipts::is_valid_object_identifier_text_v1(policy_oid) {
            return tsa_smoke_fail_v1(
                opts,
                root_paths,
                Vec::new(),
                0,
                "--tsa-policy-oid must be a valid dotted object identifier",
            );
        }
    }
    if opts.tsa_root_cert_paths.is_empty() {
        return tsa_smoke_fail_v1(
            opts,
            root_paths,
            Vec::new(),
            0,
            "--tsa-root-cert is required at least once when --tsa-enabled is set",
        );
    }

    let mut cert_count = 0usize;
    let mut fingerprints = Vec::new();
    for path in opts.tsa_root_cert_paths {
        let cert_bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) => {
                return tsa_smoke_fail_v1(
                    opts,
                    root_paths,
                    fingerprints,
                    cert_count,
                    &format!("failed to read TSA root certificate {}: {err}", path.display()),
                )
            }
        };
        let certs = match corecrux_receipts::parse_x509_certs_der_or_pem_v1(&cert_bytes) {
            Ok(certs) => certs,
            Err(err) => {
                return tsa_smoke_fail_v1(
                    opts,
                    root_paths,
                    fingerprints,
                    cert_count,
                    &format!("failed to parse TSA root certificate {}: {err}", path.display()),
                )
            }
        };
        fingerprints.extend(certs.iter().map(|cert| format!("sha256:{}", sha256_hex(cert))));
        cert_count += certs.len();
    }

    TsaProviderSmokeReportV1 {
        enabled: true,
        configured: true,
        ok: true,
        tsa_url: opts.tsa_url.map(str::to_string),
        tsa_root_cert_paths: root_paths,
        tsa_root_cert_sha256_fingerprints: fingerprints,
        tsa_root_cert_count: cert_count,
        tsa_policy_oid: opts.tsa_policy_oid.map(str::to_string),
        failure_reason: None,
    }
}

fn tsa_smoke_fail_v1(
    opts: &WitnessSmokeOptionsV1<'_>,
    root_paths: Vec<String>,
    tsa_root_cert_sha256_fingerprints: Vec<String>,
    tsa_root_cert_count: usize,
    reason: &str,
) -> TsaProviderSmokeReportV1 {
    TsaProviderSmokeReportV1 {
        enabled: true,
        configured: false,
        ok: false,
        tsa_url: opts.tsa_url.map(str::to_string),
        tsa_root_cert_paths: root_paths,
        tsa_root_cert_sha256_fingerprints,
        tsa_root_cert_count,
        tsa_policy_oid: opts.tsa_policy_oid.map(str::to_string),
        failure_reason: Some(reason.to_string()),
    }
}

pub fn parse_hex_bytes_v1(raw: &str) -> Result<Vec<u8>, String> {
    let raw = raw.strip_prefix("0x").unwrap_or(raw);
    if raw.is_empty() || raw.len() % 2 != 0 {
        return Err("hex value must contain an even number of digits".to_string());
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    for chunk in raw.as_bytes().chunks_exact(2) {
        let hi = hex_val_v1(chunk[0])?;
        let lo = hex_val_v1(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn looks_https_url(url: &str) -> bool {
    url.trim_start().starts_with("https://")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn hex_val_v1(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err("hex value contains a non-hex digit".to_string()),
    }
}

pub fn seed_minimal_receipt_v1(
    data_dir: &Path,
    shard_id: u32,
    tenant_id: &str,
    receipt_id: &str,
    _device_index: i32,
) -> Result<ReceiptsSeedReportV1, Box<dyn std::error::Error + Send + Sync>> {
    let shard_root = data_dir.join("shards");
    std::fs::create_dir_all(&shard_root)?;

    // Default Phase 8 keyring location.
    let keyring_path = data_dir.join("meta").join("keys").join("ed25519-keyring.json");
    if let Some(parent) = keyring_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Dev-only fixed signing key for repeatable local seeding.
    const DEV_SK_BYTES: [u8; 32] = [42u8; 32];
    let sk = SigningKey::from_bytes(&DEV_SK_BYTES);
    let vk = sk.verifying_key();
    let key_id = "dev-k1";

    let wrote_keyring = if keyring_path.exists() {
        false
    } else {
        let keyring = Ed25519KeyRingV1 {
            v: 1,
            keys: vec![Ed25519KeyEntryV1 {
                key_id: key_id.to_string(),
                pub_key_base64: base64::engine::general_purpose::STANDARD.encode(vk.as_bytes()),
            }],
        };
        let bytes = serde_json::to_vec_pretty(&keyring)?;
        std::fs::write(&keyring_path, &bytes)?;
        true
    };

    // Build a minimal valid CBOR receipt body (producers own canonicalization).
    let body_val = ciborium::value::Value::Map(vec![
        (
            ciborium::value::Value::Text("schema".to_string()),
            ciborium::value::Value::Text("cuecrux.receipt.body.v1".to_string()),
        ),
        (
            ciborium::value::Value::Text("receipt_id".to_string()),
            ciborium::value::Value::Text(receipt_id.to_string()),
        ),
        (
            ciborium::value::Value::Text("tenant_id".to_string()),
            ciborium::value::Value::Text(tenant_id.to_string()),
        ),
        (
            ciborium::value::Value::Text("kind".to_string()),
            ciborium::value::Value::Text("answer".to_string()),
        ),
        (
            ciborium::value::Value::Text("mode".to_string()),
            ciborium::value::Value::Text("verified".to_string()),
        ),
    ]);
    let mut body_bytes = Vec::new();
    ciborium::ser::into_writer(&body_val, &mut body_bytes)?;

    let payload_hash = corecrux_frame::compute_payload_hash(&body_bytes);
    let sig64 = sk.sign(&body_bytes).to_bytes().to_vec();

    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let sig = ReceiptSigV1 {
        schema: "cuecrux.receipt.sig.v1".to_string(),
        receipt_id: receipt_id.to_string(),
        alg: "ed25519".to_string(),
        key_id: key_id.to_string(),
        signed_at: now.clone(),
        signature: sig64,
        signed_payload_hash: payload_hash.to_vec(),
    };
    let mut sig_bytes = Vec::new();
    ciborium::ser::into_writer(&sig, &mut sig_bytes)?;

    let epoch = 1u64;
    let mut storage = ShardStorage::open(&shard_root, shard_id, epoch, ShardStorageOptions::default())?;

    let stream_hash = stream_hash_xxhash64(tenant_id, STREAM_TYPE_RECEIPT, receipt_id)?;

    // Deterministic-ish event IDs for idempotent replays.
    let body_event_id = format!("seed:receipt:{receipt_id}:body");
    let sig_event_id = format!("seed:receipt:{receipt_id}:sig");

    let inputs = [
        AppendEventInput {
            event_id: &body_event_id,
            occurred_at: &now,
            event_type: EVT_RECEIPT_BODY_V1,
            content_type: CONTENT_TYPE_RECEIPT_BODY_V1,
            payload_bytes: &body_bytes,
        },
        AppendEventInput {
            event_id: &sig_event_id,
            occurred_at: &now,
            event_type: EVT_RECEIPT_SIG_V1,
            content_type: CONTENT_TYPE_RECEIPT_SIG_V1,
            payload_bytes: &sig_bytes,
        },
    ];

    let outcomes = storage.append_batch(
        stream_hash,
        /*expected_next_seq=*/ 0,
        tenant_id,
        STREAM_TYPE_RECEIPT,
        receipt_id,
        &now,
        &inputs,
    )?;

    let outcomes = outcomes
        .into_iter()
        .map(|o| SeedOutcomeV1 {
            status: match o.status {
                corecrux_storage::AppendStatus::Appended => "APPENDED".to_string(),
                corecrux_storage::AppendStatus::DuplicateCommitted => "DUPLICATE_COMMITTED".to_string(),
                corecrux_storage::AppendStatus::DuplicateInBatch => "DUPLICATE_IN_BATCH".to_string(),
                corecrux_storage::AppendStatus::Rejected => "REJECTED".to_string(),
            },
            seq: o.seq,
            location: o.location.map(|loc| SeedFrameLocationV1 {
                shard_id: loc.shard_id,
                epoch: loc.epoch,
                segment_seq: loc.segment_seq,
                offset: loc.offset,
            }),
            payload_hash: hex32(&o.payload_hash),
            header_hash: hex32(&o.header_hash),
            error_code: o.error_code,
            error_message: o.error_message,
        })
        .collect();

    Ok(ReceiptsSeedReportV1 {
        data_dir: data_dir.display().to_string(),
        shard_id,
        tenant_id: tenant_id.to_string(),
        receipt_id: receipt_id.to_string(),
        stream_hash: corecrux_types::format_u64_hex(stream_hash),
        keyring_path: keyring_path.display().to_string(),
        wrote_keyring,
        outcomes,
    })
}

pub fn backfill_subject_index_v1(
    data_dir: &Path,
    shard: Option<u32>,
    dry_run: bool,
    _device_index: i32,
    batch_frames: u32,
) -> Result<BackfillSubjectIndexReportV1, Box<dyn std::error::Error + Send + Sync>> {
    let shard_root = data_dir.join("shards");
    if !shard_root.exists() {
        return Err(format!("shard root not found: {}", shard_root.display()).into());
    }

    let subject_index_root = data_dir.join("meta").join("receipts").join("subjects");
    if !dry_run {
        std::fs::create_dir_all(&subject_index_root)?;
    }

    let shards = if let Some(id) = shard {
        vec![id]
    } else {
        list_shards(&shard_root)?
    };

    let mut out_shards: Vec<BackfillShardReportV1> = Vec::new();
    let mut totals = BackfillTotalsV1::default();

    for shard_id in shards {
        let storage = ShardStorage::open(&shard_root, shard_id, /*epoch=*/ 1, ShardStorageOptions::default())?;

        let mut rep = BackfillShardReportV1 {
            shard_id,
            scanned_frames: 0,
            receipt_body_frames: 0,
            indexed: 0,
            skipped_no_subject: 0,
            skipped_kind_other: 0,
            parse_failed: 0,
        };

        let mut cursor: Option<corecrux_storage::ReplayCursor> = None;
        loop {
            let (frames, next) = storage.replay_from(cursor, batch_frames)?;
            if frames.is_empty() {
                break;
            }
            for (_loc, frame_bytes) in frames {
                rep.scanned_frames += 1;

                let frame = match decode_frame_v1(&frame_bytes) {
                    Ok(v) => v,
                    Err(_) => {
                        rep.parse_failed += 1;
                        continue;
                    }
                };
                let hdr = match decode_canonical_header_bytes_v1(&frame.header_bytes) {
                    Ok(h) => h,
                    Err(_) => {
                        rep.parse_failed += 1;
                        continue;
                    }
                };

                if hdr.stream_type != STREAM_TYPE_RECEIPT || hdr.event_type != EVT_RECEIPT_BODY_V1 {
                    continue;
                }
                rep.receipt_body_frames += 1;

                let idx = match corecrux_receipts::extract_body_index_v1(&frame.payload_bytes) {
                    Some(v) => v,
                    None => {
                        rep.parse_failed += 1;
                        continue;
                    }
                };

                let Some(kind) = idx.kind.as_deref() else {
                    rep.skipped_kind_other += 1;
                    continue;
                };
                if kind != "answer" && kind != "action" {
                    rep.skipped_kind_other += 1;
                    continue;
                }

                let Some(subject_id) = idx.subject_id.as_deref() else {
                    rep.skipped_no_subject += 1;
                    continue;
                };

                let mode = idx.mode.as_deref().unwrap_or("unknown");
                if dry_run {
                    let _ =
                        corecrux_receipts::subject_index_path_v1(&subject_index_root, &hdr.tenant_id, kind, subject_id);
                } else {
                    update_subject_index_v1(
                        &subject_index_root,
                        &hdr.tenant_id,
                        kind,
                        subject_id,
                        &hdr.stream_id,
                        mode,
                        &hdr.ingested_at,
                    )?;
                }
                rep.indexed += 1;
            }

            cursor = next;
            if cursor.is_none() {
                break;
            }
        }

        totals.shards += 1;
        totals.scanned_frames += rep.scanned_frames;
        totals.receipt_body_frames += rep.receipt_body_frames;
        totals.indexed += rep.indexed;
        totals.skipped_no_subject += rep.skipped_no_subject;
        totals.skipped_kind_other += rep.skipped_kind_other;
        totals.parse_failed += rep.parse_failed;

        out_shards.push(rep);
    }

    Ok(BackfillSubjectIndexReportV1 {
        data_dir: data_dir.display().to_string(),
        subject_index_root: subject_index_root.display().to_string(),
        dry_run,
        shards: out_shards,
        totals,
    })
}

fn decode_fixed_32_b64(field: &'static str, value: &str) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|err| format!("{field} is not valid base64: {err}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{field} must decode to 32 bytes").into())
}

fn decode_fixed_24_b64(field: &'static str, value: &str) -> Result<[u8; 24], Box<dyn std::error::Error + Send + Sync>> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|err| format!("{field} is not valid base64: {err}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{field} must decode to 24 bytes").into())
}

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    String::from_utf8_lossy(&out).to_string()
}

fn write_parented(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, bytes)?;
    Ok(())
}

fn list_shards(shard_root: &Path) -> Result<Vec<u32>, Box<dyn std::error::Error + Send + Sync>> {
    let mut out = Vec::<u32>::new();
    for ent in std::fs::read_dir(shard_root)? {
        let ent = ent?;
        if !ent.file_type()?.is_dir() {
            continue;
        }
        let Some(name) = ent.file_name().to_str().map(|s| s.to_string()) else {
            continue;
        };
        let Some(rest) = name.strip_prefix("shard-") else {
            continue;
        };
        let Ok(id) = rest.parse::<u32>() else {
            continue;
        };
        out.push(id);
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn hex32_zero_bytes() {
        let bytes = [0u8; 32];
        assert_eq!(hex32(&bytes), "0".repeat(64));
    }

    #[test]
    fn hex32_all_ff() {
        let bytes = [0xffu8; 32];
        assert_eq!(hex32(&bytes), "f".repeat(64));
    }

    #[test]
    fn hex32_known_value() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xde;
        bytes[1] = 0xad;
        let hex = hex32(&bytes);
        assert!(hex.starts_with("dead"));
        assert_eq!(hex.len(), 64);
    }

    #[test]
    fn receipts_seed_report_serializes() {
        let report = ReceiptsSeedReportV1 {
            data_dir: "/tmp".to_string(),
            shard_id: 1,
            tenant_id: "t".to_string(),
            receipt_id: "r1".to_string(),
            stream_hash: "0x1234".to_string(),
            keyring_path: "/tmp/keyring.json".to_string(),
            wrote_keyring: true,
            outcomes: vec![SeedOutcomeV1 {
                status: "APPENDED".to_string(),
                seq: 0,
                location: Some(SeedFrameLocationV1 {
                    shard_id: 1,
                    epoch: 1,
                    segment_seq: 0,
                    offset: 0,
                }),
                payload_hash: "aa".repeat(32),
                header_hash: "bb".repeat(32),
                error_code: None,
                error_message: None,
            }],
        };
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("\"receipt_id\":\"r1\""));
        assert!(json.contains("\"wrote_keyring\":true"));
    }

    #[test]
    fn redaction_attest_stages_crypto_shred_envelope_without_key_material() {
        let dir = tempfile::tempdir().unwrap();
        let plaintext_path = dir.path().join("plain.txt");
        let body_path = dir.path().join("redaction.cbor");
        let envelope_path = dir.path().join("envelope.json");
        std::fs::write(&plaintext_path, b"erase me").unwrap();

        let report = write_redaction_attestation_v1(&RedactionAttestOptionsV1 {
            out_body: &body_path,
            out_sig: None,
            signing_key_b64: None,
            key_id: "redaction-attest",
            signed_at: "2026-06-14T10:00:00Z",
            tenant_id: "tenant-a",
            receipt_id: "red_1",
            redaction_id: "red_1",
            actor_passport: "passport:operator",
            subject_type: "fact",
            subject_id: "f_1",
            request_id: "forget_1",
            scope: "subject",
            method: "crypto_shred",
            subject_cek_id: "cek:tenant-a:fact:f_1:v1",
            subject_cek_commitment: None,
            cek_destroyed_at: None,
            prior_content_hash: None,
            redacted_content_hash: None,
            linked_receipts: &["forget_1"],
            created_at: "2026-06-14T10:00:00Z",
            crypto_shred_staged: true,
            seal_plaintext: Some(&plaintext_path),
            out_envelope: Some(&envelope_path),
            cek_b64: Some("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="),
            nonce_b64: Some("CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJ"),
        })
        .unwrap();

        assert!(body_path.exists());
        assert!(envelope_path.exists());
        assert!(report.crypto_shred_staged);
        assert!(report.prior_content_hash.as_deref().unwrap().starts_with("blake3:"));
        assert!(report.redacted_content_hash.as_deref().unwrap().starts_with("blake3:"));
        let envelope_json = std::fs::read_to_string(&envelope_path).unwrap();
        assert!(envelope_json.contains("\"ciphertext_b64\""));
        assert!(!envelope_json.contains("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="));
        assert!(!envelope_json.contains("erase me"));
    }

    #[test]
    fn crypto_shred_destroy_marker_writes_non_destructive_marker() {
        let dir = tempfile::tempdir().unwrap();
        let marker_path = dir.path().join("destroy-marker.json");
        let report = write_crypto_shred_destroy_marker_v1(&CryptoShredDestroyMarkerOptionsV1 {
            out_marker: &marker_path,
            marker_id: "destroy_1",
            tenant_id: "tenant-a",
            subject_type: "fact",
            subject_id: "f_1",
            subject_cek_id: "cek:tenant-a:fact:f_1:v1",
            subject_cek_commitment: "blake3:commitment",
            redaction_receipt_id: "red_1",
            actor_passport: "passport:operator",
            idempotency_key: "destroy:f_1:v1",
            requested_at: "2026-06-14T10:00:00Z",
            destroyed_at: None,
            human_gate_receipt: None,
            wrapped_key_ref: Some("vault://tenant-a/cek/f_1/v1"),
            reason: Some("subject erasure request"),
            linked_receipts: &["forget_1", "red_1"],
        })
        .unwrap();

        assert!(marker_path.exists());
        assert_eq!(report.marker_id, "destroy_1");
        assert_eq!(report.state, "destroy_requested");
        assert_eq!(report.linked_receipts_count, 2);
        assert!(report.human_gate_required);
        assert!(!report.destructive_action_performed);
        let marker_json = std::fs::read_to_string(marker_path).unwrap();
        assert!(marker_json.contains("\"schema\": \"cuecrux.crypto_shred.destroy_marker.v1\""));
        assert!(marker_json.contains("\"red_1\""));
        assert!(!marker_json.contains("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="));
    }

    #[test]
    fn crypto_shred_destroy_marker_rejects_destroyed_without_human_gate() {
        let dir = tempfile::tempdir().unwrap();
        let marker_path = dir.path().join("destroy-marker.json");
        let err = write_crypto_shred_destroy_marker_v1(&CryptoShredDestroyMarkerOptionsV1 {
            out_marker: &marker_path,
            marker_id: "destroy_1",
            tenant_id: "tenant-a",
            subject_type: "fact",
            subject_id: "f_1",
            subject_cek_id: "cek:tenant-a:fact:f_1:v1",
            subject_cek_commitment: "blake3:commitment",
            redaction_receipt_id: "red_1",
            actor_passport: "passport:operator",
            idempotency_key: "destroy:f_1:v1",
            requested_at: "2026-06-14T10:00:00Z",
            destroyed_at: Some("2026-06-14T10:05:00Z"),
            human_gate_receipt: None,
            wrapped_key_ref: None,
            reason: None,
            linked_receipts: &[],
        })
        .unwrap_err();

        assert!(err.to_string().contains("human gate receipt"));
        assert!(!marker_path.exists());
    }

    #[test]
    fn chain_reanchor_attest_writes_body_that_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let body_path = dir.path().join("chain.cbor");
        let report = write_chain_reanchor_attestation_v1(&ChainReanchorAttestOptionsV1 {
            out_body: &body_path,
            out_sig: None,
            signing_key_b64: None,
            key_id: "chain-reanchor",
            signed_at: "2026-06-14T10:00:00Z",
            tenant_id: "tenant-a",
            receipt_id: "cr_1",
            migration_id: "migration-1",
            actor_passport: "passport:operator",
            old_chain_head: "blake3:old",
            new_chain_head: "blake3:new",
            old_hash_alg: "blake3",
            new_hash_alg: "blake3+external-anchor",
            first_receipt_id: "r_1",
            last_receipt_id: "r_2",
            receipt_count: 2,
            reason: "external-anchor-upgrade",
            linked_receipts: &["anchor_1"],
            created_at: "2026-06-14T10:00:00Z",
        })
        .unwrap();
        assert!(body_path.exists());
        assert!(report.verified);
        assert_eq!(report.linked_receipts_count, 1);

        let verify = verify_chain_reanchor_body_file_v1(&body_path).unwrap();
        assert!(verify.ok);
        assert!(verify.failure_reason.is_none());
    }

    #[test]
    fn external_anchor_attest_writes_body_that_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let body_path = dir.path().join("anchor.cbor");
        let leaf = "00".repeat(32);
        let report = write_external_anchor_attestation_v1(&ExternalAnchorAttestOptionsV1 {
            out_body: &body_path,
            out_sig: None,
            signing_key_b64: None,
            key_id: "external-anchor",
            signed_at: "2026-06-14T10:00:00Z",
            tenant_id: "tenant-a",
            receipt_id: "anchor_receipt_1",
            anchor_id: "anchor-1",
            actor_passport: "passport:operator",
            transparency_log: "rekor",
            log_url: "https://rekor.example",
            rekor_uuid: Some("uuid-1"),
            leaf_hash: &leaf,
            log_index: 0,
            tree_size: 1,
            root_hash: &leaf,
            inclusion_proof: &[],
            checkpoint: None,
            integrated_time: "2026-06-14T10:00:00Z",
            created_at: "2026-06-14T10:00:00Z",
        })
        .unwrap();
        assert!(body_path.exists());
        assert_eq!(report.kind, "external_anchor");
        assert!(report.verified);

        let verify = verify_external_anchor_body_file_v1(&body_path).unwrap();
        assert!(verify.ok);
    }

    #[test]
    fn rfc3161_timestamp_attest_writes_body_that_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let body_path = dir.path().join("tsa.cbor");
        let token_path = dir.path().join("token.der");
        std::fs::write(&token_path, b"fixture-token").unwrap();
        let imprint = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let report = write_rfc3161_timestamp_attestation_v1(&Rfc3161TimestampAttestOptionsV1 {
            out_body: &body_path,
            out_sig: None,
            signing_key_b64: None,
            key_id: "rfc3161-timestamp",
            signed_at: "2026-06-14T10:00:00Z",
            tenant_id: "tenant-a",
            receipt_id: "tsa_1",
            timestamp_id: "timestamp-1",
            actor_passport: "passport:operator",
            tsa_url: "https://tsa.example",
            tsa_policy_oid: Some("1.2.3.4"),
            message_imprint_alg: "sha256",
            message_imprint_hash: imprint,
            timestamp_token_der: &token_path,
            serial_number: Some("01"),
            gen_time: "2026-06-14T10:00:00Z",
            created_at: "2026-06-14T10:00:00Z",
        })
        .unwrap();
        assert!(body_path.exists());
        assert_eq!(report.kind, "rfc3161_timestamp");
        assert!(report.verified);

        let verify = verify_rfc3161_timestamp_body_file_v1(&body_path, Some(imprint)).unwrap();
        assert!(verify.ok);
    }

    #[test]
    fn backfill_totals_default_is_zero() {
        let t = BackfillTotalsV1::default();
        assert_eq!(t.shards, 0);
        assert_eq!(t.scanned_frames, 0);
        assert_eq!(t.receipt_body_frames, 0);
        assert_eq!(t.indexed, 0);
        assert_eq!(t.skipped_no_subject, 0);
        assert_eq!(t.skipped_kind_other, 0);
        assert_eq!(t.parse_failed, 0);
    }

    #[test]
    fn backfill_subject_index_report_serializes() {
        let report = BackfillSubjectIndexReportV1 {
            data_dir: "/tmp".to_string(),
            subject_index_root: "/tmp/subjects".to_string(),
            dry_run: true,
            shards: vec![BackfillShardReportV1 {
                shard_id: 1,
                scanned_frames: 100,
                receipt_body_frames: 10,
                indexed: 5,
                skipped_no_subject: 2,
                skipped_kind_other: 3,
                parse_failed: 0,
            }],
            totals: BackfillTotalsV1 {
                shards: 1,
                scanned_frames: 100,
                receipt_body_frames: 10,
                indexed: 5,
                skipped_no_subject: 2,
                skipped_kind_other: 3,
                parse_failed: 0,
            },
        };
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("\"dry_run\":true"));
        assert!(json.contains("\"scanned_frames\":100"));
    }

    #[test]
    fn witness_verify_report_serializes() {
        let report = WitnessVerifyReportV1 {
            body_path: "/tmp/body.cbor".to_string(),
            kind: "external_anchor".to_string(),
            ok: false,
            failure_reason: Some("bad proof".to_string()),
            strict_validation: None,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"kind\":\"external_anchor\""));
        assert!(json.contains("\"ok\":false"));
        assert!(json.contains("bad proof"));
    }

    #[test]
    fn coverage_attest_writes_body_and_signature() {
        let tmp = tempfile::tempdir().unwrap();
        let report_path = tmp.path().join("coverage.json");
        std::fs::write(&report_path, br#"{"coverage":0.92}"#).unwrap();
        let body_path = tmp.path().join("out/body.cbor");
        let sig_path = tmp.path().join("out/body.sig.cbor");
        let signing_key = SigningKey::from_bytes(&[99u8; 32]);
        let signing_key_b64 = base64::engine::general_purpose::STANDARD.encode(signing_key.to_bytes());

        let report = write_coverage_attestation_v1(
            &body_path,
            Some(&sig_path),
            Some(&signing_key_b64),
            "coverage-key",
            "2026-06-14T10:00:01Z",
            "tenant-a",
            "cov_1",
            "coverage-1",
            "passport:agent",
            "feature_registry",
            "LME-S",
            "run-1",
            "deadbeef",
            "dense=on,sparse=on",
            "capability_coverage",
            0.92,
            Some(0.9),
            0,
            Some(100),
            Some(92),
            Some("blake3:gaps"),
            &report_path,
            "2026-06-14T10:00:00Z",
        )
        .unwrap();

        assert!(body_path.exists());
        assert!(sig_path.exists());
        assert!(report.signed);
        assert!(report.report_hash.starts_with("blake3:"));
        let body = std::fs::read(body_path).unwrap();
        assert!(corecrux_receipts::assert_coverage_attestation_kind_v1(&body));
    }

    // ── coverage_window_attest_v1 ───────────────────────────────────

    /// Append one frame (event or receipt body) into a shard with an
    /// explicit `ingested_at` so the window scan is deterministic.
    fn seed_frame(
        storage: &mut ShardStorage,
        tenant: &str,
        stream_type: &str,
        stream_id: &str,
        event_type: &str,
        content_type: &str,
        ingested_at: &str,
        payload: &[u8],
    ) {
        use corecrux_frame::stream_hash_xxhash64;
        let stream_hash = stream_hash_xxhash64(tenant, stream_type, stream_id).unwrap();
        let event_id = format!("seed:{stream_type}:{stream_id}:{event_type}");
        let inputs = [AppendEventInput {
            event_id: &event_id,
            occurred_at: ingested_at,
            event_type,
            content_type,
            payload_bytes: payload,
        }];
        storage
            .append_batch(stream_hash, 0, tenant, stream_type, stream_id, ingested_at, &inputs)
            .unwrap();
    }

    fn anchor_body_linking(tenant: &str, receipt_id: &str, anchor_id: &str, linked: &str) -> Vec<u8> {
        let leaf = "00".repeat(32);
        // build_external_anchor_body_v1 has no linked_receipts field, so append
        // one via a wrapper map is not possible; instead we link by anchoring
        // a receipt whose id we also seed as a plain receipt. The scan treats
        // an anchor body's own receipt_id as anchored, and linked_receipts when
        // present. Here we exercise the anchor-kind path; `linked` is the id we
        // also seed as a plain receipt to assert it stays unanchored.
        let _ = linked;
        let input = corecrux_receipts::ExternalAnchorBodyInputV1 {
            tenant_id: tenant,
            receipt_id,
            anchor_id,
            actor_passport: "passport:operator",
            transparency_log: "rekor",
            log_url: "https://rekor.example",
            rekor_uuid: Some("uuid-1"),
            leaf_hash: &leaf,
            log_index: 0,
            tree_size: 1,
            root_hash: &leaf,
            inclusion_proof: &[],
            checkpoint: None,
            integrated_time: "2026-06-14T12:00:00Z",
            created_at: "2026-06-14T12:00:00Z",
        };
        let (body, _) = corecrux_receipts::build_external_anchor_body_v1(&input);
        body
    }

    fn plain_receipt_body(receipt_id: &str, tenant: &str) -> Vec<u8> {
        let body = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("schema".into()),
                ciborium::value::Value::Text("cuecrux.receipt.body.v1".into()),
            ),
            (
                ciborium::value::Value::Text("kind".into()),
                ciborium::value::Value::Text("answer".into()),
            ),
            (
                ciborium::value::Value::Text("receipt_id".into()),
                ciborium::value::Value::Text(receipt_id.into()),
            ),
            (
                ciborium::value::Value::Text("tenant_id".into()),
                ciborium::value::Value::Text(tenant.into()),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&body, &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn coverage_window_attest_scans_signs_and_surfaces_gaps() {
        let tmp = tempfile::tempdir().unwrap();
        let shard_root = tmp.path().join("shards");
        std::fs::create_dir_all(&shard_root).unwrap();
        let tenant = "tenant-cov";
        let in_window = "2026-06-14T10:00:00Z";
        let out_window = "2026-06-20T10:00:00Z"; // after `to`, excluded
        let mut storage = ShardStorage::open(&shard_root, 1, 1, ShardStorageOptions::default()).unwrap();

        // 3 events (non-receipt, e.g. observations) in window.
        for i in 0..3 {
            seed_frame(
                &mut storage,
                tenant,
                "agent.observation",
                &format!("obs-{i}"),
                "agent.observation.body.v1",
                "application/json",
                in_window,
                format!("{{\"obs\":{i}}}").as_bytes(),
            );
        }
        // 2 plain receipt bodies in window (so 1 event lacks a receipt).
        for i in 0..2 {
            let rid = format!("r-{i}");
            seed_frame(
                &mut storage,
                tenant,
                STREAM_TYPE_RECEIPT,
                &rid,
                EVT_RECEIPT_BODY_V1,
                CONTENT_TYPE_RECEIPT_BODY_V1,
                in_window,
                &plain_receipt_body(&rid, tenant),
            );
        }
        // 1 anchor receipt body in window (anchors itself).
        seed_frame(
            &mut storage,
            tenant,
            STREAM_TYPE_RECEIPT,
            "anchor-0",
            EVT_RECEIPT_BODY_V1,
            CONTENT_TYPE_RECEIPT_BODY_V1,
            in_window,
            &anchor_body_linking(tenant, "anchor-0", "anchor-0", "r-0"),
        );
        // 1 event OUTSIDE the window — must be excluded.
        seed_frame(
            &mut storage,
            tenant,
            "agent.observation",
            "obs-late",
            "agent.observation.body.v1",
            "application/json",
            out_window,
            b"{\"obs\":\"late\"}",
        );
        // 1 event for a DIFFERENT tenant — must be excluded.
        seed_frame(
            &mut storage,
            "other-tenant",
            "agent.observation",
            "obs-other",
            "agent.observation.body.v1",
            "application/json",
            in_window,
            b"{\"obs\":\"other\"}",
        );

        // Release the shard lock before the scan re-opens the same shard.
        drop(storage);

        let signing_key = SigningKey::from_bytes(&[77u8; 32]);
        let signing_key_b64 = base64::engine::general_purpose::STANDARD.encode(signing_key.to_bytes());
        let out_report = tmp.path().join("out/window.json");
        let out_body = tmp.path().join("out/window.cbor");
        let out_sig = tmp.path().join("out/window.sig.cbor");

        let report = coverage_window_attest_v1(&CoverageWindowAttestOptionsV1 {
            data_dir: tmp.path(),
            shard: None,
            tenant_id: tenant,
            from: "2026-06-14T00:00:00Z",
            to: "2026-06-15T00:00:00Z",
            out_report: &out_report,
            out_body: &out_body,
            out_sig: Some(&out_sig),
            signing_key_b64: Some(&signing_key_b64),
            key_id: "cov-window-key",
            signed_at: "2026-06-15T00:01:00Z",
            receipt_id: "cw_1",
            attestation_id: "coverage-window-1",
            actor_passport: "passport:operator",
            created_at: "2026-06-15T00:01:00Z",
            batch_frames: 1024,
        })
        .unwrap();

        // 3 in-window, in-tenant events; the out-of-window and other-tenant
        // events are excluded.
        assert_eq!(report.events, 3, "{report:?}");
        // 3 receipt bodies (2 plain + 1 anchor).
        assert_eq!(report.receipts, 3, "{report:?}");
        // 1 anchored (the anchor body's own receipt_id).
        assert_eq!(report.anchored, 1, "{report:?}");
        // events_without_receipt = max(0, 3 - 3) = 0; receipts_without_anchor = 3 - 1 = 2.
        assert_eq!(report.events_without_receipt, 0, "{report:?}");
        assert_eq!(report.receipts_without_anchor, 2, "{report:?}");
        // gaps reconcile and are NOT hidden.
        assert_eq!(report.gaps, 2, "{report:?}");
        assert!(report.signed);
        assert!(report.verified);
        assert!(report.chain_head.starts_with("blake3:"));
        assert!(out_report.exists() && out_body.exists() && out_sig.exists());

        // The signed body verifies independently (re-read from disk).
        let body = std::fs::read(&out_body).unwrap();
        assert!(corecrux_receipts::verify_coverage_window_body_v1(&body));
        assert!(corecrux_receipts::assert_coverage_window_kind_v1(&body));

        // The detached signature checks out over the on-disk body bytes.
        let sig_bytes = std::fs::read(&out_sig).unwrap();
        let sig: ReceiptSigV1 = ciborium::de::from_reader(std::io::Cursor::new(&sig_bytes)).unwrap();
        let vk = signing_key.verifying_key();
        let sig64: [u8; 64] = sig.signature.as_slice().try_into().unwrap();
        vk.verify_strict(&body, &ed25519_dalek::Signature::from_bytes(&sig64))
            .expect("detached signature verifies over body bytes");

        // The standalone report's bound hash matches the body's report_hash.
        let report_json = std::fs::read(&out_report).unwrap();
        let parsed: corecrux_receipts::CoverageWindowReportV1 = serde_json::from_slice(&report_json).unwrap();
        assert_eq!(parsed.report_hash(), report.report_hash);
        assert_eq!(parsed.gaps, 2);
    }

    #[test]
    fn coverage_window_attest_empty_window_signs_zero_report() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("shards")).unwrap();
        let out_report = tmp.path().join("w.json");
        let out_body = tmp.path().join("w.cbor");
        let report = coverage_window_attest_v1(&CoverageWindowAttestOptionsV1 {
            data_dir: tmp.path(),
            shard: None,
            tenant_id: "tenant-empty",
            from: "2026-06-14T00:00:00Z",
            to: "2026-06-15T00:00:00Z",
            out_report: &out_report,
            out_body: &out_body,
            out_sig: None,
            signing_key_b64: None,
            key_id: "k",
            signed_at: "2026-06-15T00:01:00Z",
            receipt_id: "cw_empty",
            attestation_id: "cw_empty",
            actor_passport: "passport:operator",
            created_at: "2026-06-15T00:01:00Z",
            batch_frames: 1024,
        })
        .unwrap();
        assert_eq!(report.events, 0);
        assert_eq!(report.receipts, 0);
        assert_eq!(report.gaps, 0);
        assert!(report.verified);
        assert!(!report.signed);
        let body = std::fs::read(&out_body).unwrap();
        assert!(corecrux_receipts::verify_coverage_window_body_v1(&body));
    }

    #[test]
    fn coverage_window_attest_errors_on_missing_shard_root() {
        let tmp = tempfile::tempdir().unwrap();
        let out_report = tmp.path().join("w.json");
        let out_body = tmp.path().join("w.cbor");
        let err = coverage_window_attest_v1(&CoverageWindowAttestOptionsV1 {
            data_dir: tmp.path(),
            shard: None,
            tenant_id: "t",
            from: "2026-06-14T00:00:00Z",
            to: "2026-06-15T00:00:00Z",
            out_report: &out_report,
            out_body: &out_body,
            out_sig: None,
            signing_key_b64: None,
            key_id: "k",
            signed_at: "2026-06-15T00:01:00Z",
            receipt_id: "cw",
            attestation_id: "cw",
            actor_passport: "p",
            created_at: "2026-06-15T00:01:00Z",
            batch_frames: 1024,
        })
        .unwrap_err();
        assert!(err.to_string().contains("shard root not found"));
    }

    #[test]
    fn coverage_window_attest_report_serializes() {
        let report = CoverageWindowAttestReportV1 {
            tenant_id: "t".into(),
            from: "a".into(),
            to: "b".into(),
            events: 10,
            receipts: 8,
            anchored: 5,
            gaps: 5,
            events_without_receipt: 2,
            receipts_without_anchor: 3,
            chain_head: "blake3:00".into(),
            report_hash: "blake3:11".into(),
            report_path: "/r.json".into(),
            body_path: "/b.cbor".into(),
            sig_path: None,
            signed: false,
            verified: true,
            scanned_shards: 1,
            scanned_frames: 18,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"gaps\":5"));
        assert!(json.contains("\"verified\":true"));
    }

    #[test]
    fn verify_rfc3161_timestamp_body_file_checks_expected_imprint() {
        let tmp = tempfile::tempdir().unwrap();
        let body_path = tmp.path().join("tsa.cbor");
        let input = corecrux_receipts::Rfc3161TimestampBodyInputV1 {
            tenant_id: "tenant-a",
            receipt_id: "tsa_1",
            timestamp_id: "tsa-1",
            actor_passport: "passport:operator",
            tsa_url: "https://tsa.example",
            tsa_policy_oid: None,
            message_imprint_alg: "sha256",
            message_imprint_hash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            timestamp_token_der: b"fake-token",
            serial_number: None,
            gen_time: "2026-06-14T10:00:00Z",
            created_at: "2026-06-14T10:00:01Z",
        };
        let (body, _) = corecrux_receipts::build_rfc3161_timestamp_body_v1(&input);
        std::fs::write(&body_path, body).unwrap();

        let ok = verify_rfc3161_timestamp_body_file_v1(
            &body_path,
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        assert!(ok.ok);

        let bad = verify_rfc3161_timestamp_body_file_v1(
            &body_path,
            Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        )
        .unwrap();
        assert!(!bad.ok);
        assert!(bad.failure_reason.as_deref().unwrap_or("").contains("message imprint"));
    }

    #[test]
    fn verify_rfc3161_timestamp_with_root_enables_strict_cms_validation() {
        let tmp = tempfile::tempdir().unwrap();
        let body_path = tmp.path().join("tsa.cbor");
        let root_path = tmp.path().join("tsa-root.pem");

        let mut root_params = rcgen::CertificateParams::new(vec!["CueCrux TSA Root TEST".to_string()]).unwrap();
        root_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "CueCrux TSA Root TEST");
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let root_cert = root_params.self_signed(&root_key).unwrap();
        std::fs::write(&root_path, root_cert.pem()).unwrap();

        let input = corecrux_receipts::Rfc3161TimestampBodyInputV1 {
            tenant_id: "tenant-a",
            receipt_id: "tsa_1",
            timestamp_id: "tsa-1",
            actor_passport: "passport:operator",
            tsa_url: "https://tsa.example",
            tsa_policy_oid: Some("1.2.3.4"),
            message_imprint_alg: "sha256",
            message_imprint_hash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            timestamp_token_der: b"fake-token",
            serial_number: None,
            gen_time: "2026-06-14T10:00:00Z",
            created_at: "2026-06-14T10:00:01Z",
        };
        let (body, _) = corecrux_receipts::build_rfc3161_timestamp_body_v1(&input);
        std::fs::write(&body_path, body).unwrap();
        let root_paths = vec![root_path];

        let report = verify_rfc3161_timestamp_body_file_with_options_v1(
            &body_path,
            &Rfc3161TimestampVerifyOptionsV1 {
                expected_message_imprint_hash: Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
                expected_policy_oid: Some("1.2.3.4"),
                expected_nonce: None,
                trusted_root_cert_paths: &root_paths,
            },
        )
        .unwrap();

        assert!(!report.ok);
        let strict = report.strict_validation.expect("strict report is emitted");
        assert!(!strict.ok);
        assert!(strict.token_hash_ok);
        assert!(strict
            .failure_reason
            .as_deref()
            .unwrap_or("")
            .contains("ContentInfo parse failed"));
    }

    #[test]
    fn parse_hex_bytes_accepts_nonce_hex() {
        assert_eq!(parse_hex_bytes_v1("0x0001").unwrap(), vec![0, 1]);
        assert_eq!(parse_hex_bytes_v1("0A").unwrap(), vec![10]);
        assert!(parse_hex_bytes_v1("abc").is_err());
    }

    #[test]
    fn witness_smoke_disabled_is_ok() {
        let report = witness_smoke_v1(&WitnessSmokeOptionsV1 {
            witness_enabled: false,
            witness_provider: "disabled",
            witness_timeout_ms: 5000,
            rekor_url: None,
            rekor_public_key_path: None,
            tsa_enabled: false,
            tsa_url: None,
            tsa_root_cert_paths: &[],
            tsa_policy_oid: None,
        });
        assert!(report.ok);
        assert!(!report.witness.enabled);
        assert!(!report.tsa.enabled);
    }

    #[test]
    fn witness_smoke_validates_tsa_root_cert() {
        let tmp = tempfile::tempdir().unwrap();
        let root_path = tmp.path().join("tsa-root.pem");
        let mut root_params = rcgen::CertificateParams::new(vec!["CueCrux TSA Root TEST".to_string()]).unwrap();
        root_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "CueCrux TSA Root TEST");
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let root_cert = root_params.self_signed(&root_key).unwrap();
        std::fs::write(&root_path, root_cert.pem()).unwrap();
        let root_paths = vec![root_path];

        let report = witness_smoke_v1(&WitnessSmokeOptionsV1 {
            witness_enabled: true,
            witness_provider: "rekor",
            witness_timeout_ms: 7500,
            rekor_url: Some("https://rekor.example"),
            rekor_public_key_path: None,
            tsa_enabled: true,
            tsa_url: Some("https://tsa.example"),
            tsa_root_cert_paths: &root_paths,
            tsa_policy_oid: Some("1.2.3.4"),
        });

        assert!(report.ok, "{report:?}");
        assert!(report.witness.ok);
        assert!(report.tsa.ok);
        assert_eq!(report.tsa.tsa_root_cert_count, 1);
        assert_eq!(report.tsa.tsa_root_cert_sha256_fingerprints.len(), 1);
        assert!(report.tsa.tsa_root_cert_sha256_fingerprints[0].starts_with("sha256:"));
        assert_eq!(
            report.tsa.tsa_root_cert_sha256_fingerprints[0].len(),
            "sha256:".len() + 64
        );
        assert_eq!(report.tsa.tsa_policy_oid.as_deref(), Some("1.2.3.4"));
        assert_eq!(
            report.warnings,
            vec!["Rekor witness is enabled without --rekor-public-key-path".to_string()]
        );
    }

    #[test]
    fn witness_smoke_fails_when_enabled_tsa_lacks_root() {
        let report = witness_smoke_v1(&WitnessSmokeOptionsV1 {
            witness_enabled: false,
            witness_provider: "disabled",
            witness_timeout_ms: 5000,
            rekor_url: None,
            rekor_public_key_path: None,
            tsa_enabled: true,
            tsa_url: Some("https://tsa.example"),
            tsa_root_cert_paths: &[],
            tsa_policy_oid: None,
        });
        assert!(!report.ok);
        assert!(report
            .tsa
            .failure_reason
            .as_deref()
            .unwrap_or("")
            .contains("--tsa-root-cert"));
    }

    #[test]
    fn witness_smoke_fails_when_enabled_witness_timeout_is_zero() {
        let report = witness_smoke_v1(&WitnessSmokeOptionsV1 {
            witness_enabled: true,
            witness_provider: "rekor",
            witness_timeout_ms: 0,
            rekor_url: Some("https://rekor.example"),
            rekor_public_key_path: None,
            tsa_enabled: false,
            tsa_url: None,
            tsa_root_cert_paths: &[],
            tsa_policy_oid: None,
        });
        assert!(!report.ok);
        assert_eq!(
            report.witness.failure_reason.as_deref(),
            Some("--witness-timeout-ms must be greater than zero")
        );
    }

    #[test]
    fn witness_smoke_rejects_malformed_tsa_policy_oid_before_root_read() {
        let report = witness_smoke_v1(&WitnessSmokeOptionsV1 {
            witness_enabled: false,
            witness_provider: "disabled",
            witness_timeout_ms: 5000,
            rekor_url: None,
            rekor_public_key_path: None,
            tsa_enabled: true,
            tsa_url: Some("https://tsa.example"),
            tsa_root_cert_paths: &[PathBuf::from("/tmp/missing-root.pem")],
            tsa_policy_oid: Some("not-an-oid"),
        });
        assert!(!report.ok);
        assert_eq!(
            report.tsa.failure_reason.as_deref(),
            Some("--tsa-policy-oid must be a valid dotted object identifier")
        );
        assert!(report.tsa.tsa_root_cert_sha256_fingerprints.is_empty());
    }

    #[test]
    fn witness_smoke_warns_on_non_https_provider_urls() {
        let report = witness_smoke_v1(&WitnessSmokeOptionsV1 {
            witness_enabled: true,
            witness_provider: "rekor",
            witness_timeout_ms: 5000,
            rekor_url: Some("http://127.0.0.1:3000"),
            rekor_public_key_path: None,
            tsa_enabled: true,
            tsa_url: Some("http://127.0.0.1:3001"),
            tsa_root_cert_paths: &[PathBuf::from("/tmp/missing-root.pem")],
            tsa_policy_oid: Some("1.2.3.4"),
        });
        assert!(!report.ok);
        assert!(report
            .warnings
            .contains(&"Rekor witness URL is not HTTPS; use only for local/non-prod mocks".to_string()));
        assert!(report
            .warnings
            .contains(&"TSA URL is not HTTPS; use only for local/non-prod mocks".to_string()));
    }

    #[test]
    fn seed_outcome_serializes_without_optional_fields() {
        let outcome = SeedOutcomeV1 {
            status: "DUPLICATE_COMMITTED".to_string(),
            seq: 42,
            location: None,
            payload_hash: "a".repeat(64),
            header_hash: "b".repeat(64),
            error_code: None,
            error_message: None,
        };
        let json = serde_json::to_string(&outcome).expect("serialize");
        assert!(json.contains("\"seq\":42"));
        assert!(json.contains("\"status\":\"DUPLICATE_COMMITTED\""));
    }

    // ── seed_minimal_receipt_v1 ─────────────────────────────────────

    #[test]
    fn seed_minimal_receipt_v1_creates_keyring_and_appends() {
        let tmp = tempfile::tempdir().unwrap();
        let report = seed_minimal_receipt_v1(tmp.path(), 1, "test-tenant", "receipt-001", 0).expect("seed receipt");

        assert_eq!(report.shard_id, 1);
        assert_eq!(report.tenant_id, "test-tenant");
        assert_eq!(report.receipt_id, "receipt-001");
        assert!(report.wrote_keyring);
        assert_eq!(report.outcomes.len(), 2); // body + sig
        assert!(report.outcomes.iter().all(|o| o.status == "APPENDED"));
        // Keyring file should exist
        let keyring_path = tmp.path().join("meta/keys/ed25519-keyring.json");
        assert!(keyring_path.exists());
    }

    #[test]
    fn seed_minimal_receipt_v1_does_not_overwrite_existing_keyring() {
        let tmp = tempfile::tempdir().unwrap();
        // First call creates keyring
        let r1 = seed_minimal_receipt_v1(tmp.path(), 1, "t", "r1", 0).unwrap();
        assert!(r1.wrote_keyring);
        // Second call with different receipt should not overwrite
        let r2 = seed_minimal_receipt_v1(tmp.path(), 1, "t", "r2", 0).unwrap();
        assert!(!r2.wrote_keyring);
    }

    #[test]
    fn seed_minimal_receipt_v1_report_has_valid_stream_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let report = seed_minimal_receipt_v1(tmp.path(), 1, "t", "r1", 0).unwrap();
        // stream_hash should be a hex string starting with "0x"
        assert!(report.stream_hash.starts_with("0x"));
        assert!(report.stream_hash.len() > 2);
    }

    #[test]
    fn seed_outcome_with_error_fields_serializes() {
        let outcome = SeedOutcomeV1 {
            status: "REJECTED".to_string(),
            seq: 0,
            location: None,
            payload_hash: "c".repeat(64),
            header_hash: "d".repeat(64),
            error_code: Some("DUPLICATE".to_string()),
            error_message: Some("event already exists".to_string()),
        };
        let json = serde_json::to_string(&outcome).unwrap();
        assert!(json.contains("\"error_code\":\"DUPLICATE\""));
        assert!(json.contains("\"error_message\":\"event already exists\""));
    }

    // ── list_shards ─────────────────────────────────────────────────

    #[test]
    fn list_shards_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let shards = list_shards(tmp.path()).unwrap();
        assert!(shards.is_empty());
    }

    #[test]
    fn list_shards_finds_valid_shard_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("shard-0001")).unwrap();
        std::fs::create_dir(tmp.path().join("shard-0003")).unwrap();
        std::fs::create_dir(tmp.path().join("not-a-shard")).unwrap();
        std::fs::write(tmp.path().join("shard-0099"), b"file not dir").unwrap();

        let shards = list_shards(tmp.path()).unwrap();
        assert_eq!(shards, vec![1, 3]);
    }

    #[test]
    fn list_shards_returns_sorted_deduped() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("shard-0005")).unwrap();
        std::fs::create_dir(tmp.path().join("shard-0002")).unwrap();
        std::fs::create_dir(tmp.path().join("shard-0008")).unwrap();

        let shards = list_shards(tmp.path()).unwrap();
        assert_eq!(shards, vec![2, 5, 8]);
    }

    // ── backfill_subject_index_v1 ───────────────────────────────────

    #[test]
    fn backfill_subject_index_v1_errors_on_missing_shard_root() {
        let tmp = tempfile::tempdir().unwrap();
        // No "shards" dir inside data_dir
        let result = backfill_subject_index_v1(tmp.path(), None, false, 0, 1024);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("shard root not found"));
    }

    #[test]
    fn backfill_subject_index_v1_empty_shard_root_returns_empty_report() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("shards")).unwrap();

        let report = backfill_subject_index_v1(tmp.path(), None, false, 0, 1024).unwrap();
        assert_eq!(report.totals.shards, 0);
        assert_eq!(report.totals.scanned_frames, 0);
        assert!(report.shards.is_empty());
    }

    #[test]
    fn backfill_subject_index_v1_dry_run_returns_report() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("shards")).unwrap();

        let report = backfill_subject_index_v1(tmp.path(), None, true, 0, 1024).unwrap();
        assert!(report.dry_run);
        assert_eq!(report.totals.shards, 0);
    }

    // ── BackfillShardReportV1 serialization ─────────────────────────

    #[test]
    fn backfill_shard_report_serializes() {
        let report = BackfillShardReportV1 {
            shard_id: 2,
            scanned_frames: 50,
            receipt_body_frames: 5,
            indexed: 3,
            skipped_no_subject: 1,
            skipped_kind_other: 1,
            parse_failed: 0,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"shard_id\":2"));
        assert!(json.contains("\"indexed\":3"));
    }

    // ── SeedFrameLocationV1 ─────────────────────────────────────────

    // ── hex32 edge cases ─────────────────────────────────────────────

    #[test]
    fn hex32_mixed_values() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x12;
        bytes[1] = 0x34;
        bytes[31] = 0xAB;
        let hex = hex32(&bytes);
        assert!(hex.starts_with("1234"));
        assert!(hex.ends_with("ab"));
        assert_eq!(hex.len(), 64);
    }

    // ── list_shards: non-numeric shard name ─────────────────────────

    #[test]
    fn list_shards_ignores_non_numeric() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("shard-abc")).unwrap();
        std::fs::create_dir(tmp.path().join("shard-0001")).unwrap();
        let shards = list_shards(tmp.path()).unwrap();
        assert_eq!(shards, vec![1]);
    }

    // ── ReceiptsSeedReportV1: empty outcomes ────────────────────────

    #[test]
    fn receipts_seed_report_empty_outcomes() {
        let report = ReceiptsSeedReportV1 {
            data_dir: "/d".to_string(),
            shard_id: 0,
            tenant_id: "t".to_string(),
            receipt_id: "r".to_string(),
            stream_hash: "0x0".to_string(),
            keyring_path: "/k".to_string(),
            wrote_keyring: false,
            outcomes: Vec::new(),
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"outcomes\":[]"));
        assert!(json.contains("\"wrote_keyring\":false"));
    }

    // ── BackfillTotalsV1: accumulation ─────────────────────────────

    #[test]
    fn backfill_totals_accumulation() {
        let mut t = BackfillTotalsV1::default();
        t.shards += 2;
        t.scanned_frames += 100;
        t.receipt_body_frames += 20;
        t.indexed += 15;
        t.skipped_no_subject += 3;
        t.skipped_kind_other += 1;
        t.parse_failed += 1;
        assert_eq!(t.shards, 2);
        assert_eq!(t.scanned_frames, 100);
        assert_eq!(t.indexed, 15);
    }

    // ── SeedOutcomeV1: all status variants ──────────────────────────

    #[test]
    fn seed_outcome_all_status_variants() {
        for status_str in ["APPENDED", "DUPLICATE_COMMITTED", "DUPLICATE_IN_BATCH", "REJECTED"] {
            let outcome = SeedOutcomeV1 {
                status: status_str.to_string(),
                seq: 0,
                location: None,
                payload_hash: "0".repeat(64),
                header_hash: "0".repeat(64),
                error_code: None,
                error_message: None,
            };
            let json = serde_json::to_string(&outcome).unwrap();
            assert!(json.contains(status_str));
        }
    }

    // ── SeedFrameLocationV1: all fields ─────────────────────────────

    #[test]
    fn seed_frame_location_all_fields() {
        let loc = SeedFrameLocationV1 {
            shard_id: 99,
            epoch: 42,
            segment_seq: 7,
            offset: 8192,
        };
        let json = serde_json::to_value(&loc).unwrap();
        assert_eq!(json["shard_id"], 99);
        assert_eq!(json["epoch"], 42);
        assert_eq!(json["segment_seq"], 7);
        assert_eq!(json["offset"], 8192);
    }

    #[test]
    fn seed_frame_location_serializes() {
        let loc = SeedFrameLocationV1 {
            shard_id: 1,
            epoch: 1,
            segment_seq: 0,
            offset: 128,
        };
        let json = serde_json::to_string(&loc).unwrap();
        assert!(json.contains("\"offset\":128"));
    }
}
