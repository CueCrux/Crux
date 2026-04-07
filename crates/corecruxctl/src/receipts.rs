// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::path::Path;

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};

use corecrux_frame::{decode_canonical_header_bytes_v1, stream_hash_xxhash64};
use corecrux_receipts::{
    update_subject_index_v1, Ed25519KeyEntryV1, Ed25519KeyRingV1, ReceiptSigV1, CONTENT_TYPE_RECEIPT_BODY_V1,
    CONTENT_TYPE_RECEIPT_SIG_V1, EVT_RECEIPT_BODY_V1, EVT_RECEIPT_SIG_V1, STREAM_TYPE_RECEIPT,
};
use corecrux_segment::decode_frame_v1;
use corecrux_storage::{AppendEventInput, ShardStorage, ShardStorageOptions};

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

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    String::from_utf8_lossy(&out).to_string()
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
