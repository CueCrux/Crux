// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Receipt-tooling — sign receipts with an Ed25519 key, encode + decode CROWN bodies, base64 IO.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};

use corecrux_frame::{decode_canonical_header_bytes_v1, stream_hash_xxhash64};
use corecrux_receipts::{
    assert_external_anchor_kind_v1, assert_rfc3161_timestamp_kind_v1, seal_crypto_shred_payload_v1,
    update_subject_index_v1, verify_chain_reanchor_body_v1, verify_external_anchor_body_v1,
    verify_rfc3161_timestamp_token_binding_v1, verify_rfc3161_timestamp_token_strict_v1, ChainReanchorBodyInputV1,
    CoverageAttestationBodyInputV1, CryptoShredSealInputV1, Ed25519KeyEntryV1, Ed25519KeyRingV1,
    ExternalAnchorBodyInputV1, ReceiptSigV1, RedactionReceiptBodyInputV1, Rfc3161StrictValidationOptionsV1,
    Rfc3161StrictValidationReportV1, Rfc3161TimestampBodyInputV1, CONTENT_TYPE_RECEIPT_BODY_V1,
    CONTENT_TYPE_RECEIPT_SIG_V1, EVT_RECEIPT_BODY_V1, EVT_RECEIPT_SIG_V1, STREAM_TYPE_RECEIPT,
};
use corecrux_segment::decode_frame_v1;
use corecrux_storage::{AppendEventInput, ShardStorage, ShardStorageOptions};

type ReceiptSignerV1 = fn(&str, &[u8], [u8; 32], &SigningKey, &str, &str) -> ReceiptSigV1;

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
pub struct CoverageAttestReportV1 {
    pub body_path: String,
    pub sig_path: Option<String>,
    pub receipt_id: String,
    pub attestation_id: String,
    pub report_hash: String,
    pub signed: bool,
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
