// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::path::{Path, PathBuf};
use std::time::Instant;

use corecrux_storage::{ReplayScanStats, ShardStorage, ShardStorageOptions};

#[derive(Debug, Clone, Copy, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VerifyScope {
    Recent,
    All,
}

impl VerifyScope {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "recent" => Some(Self::Recent),
            "all" => Some(Self::All),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VerifyMode {
    Sampled,
    Full,
}

impl VerifyMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "sampled" => Some(Self::Sampled),
            "full" => Some(Self::Full),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifyStoreOptions {
    pub data_dir: PathBuf,
    pub shard: Option<u32>,
    pub scope: VerifyScope,
    pub mode: VerifyMode,
    pub sample_rate: f64,
    pub budget_bytes: usize,
    pub device_index: i32,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyStoreStats {
    pub total_segments: u64,
    pub total_blocks: u64,
    pub total_frames: u64,
    pub total_compressed_bytes: u64,
    pub total_uncompressed_bytes: u64,
}

impl From<ReplayScanStats> for VerifyStoreStats {
    fn from(v: ReplayScanStats) -> Self {
        Self {
            total_segments: v.total_segments,
            total_blocks: v.total_blocks,
            total_frames: v.total_frames,
            total_compressed_bytes: v.total_compressed_bytes,
            total_uncompressed_bytes: v.total_uncompressed_bytes,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyStoreShardReport {
    #[serde(rename = "shardId")]
    pub shard_id: u32,
    pub epoch: u64,
    pub scanned: bool,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(rename = "elapsedMs")]
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<VerifyStoreStats>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyStoreReport {
    pub ok: bool,
    #[serde(rename = "dataDir")]
    pub data_dir: String,
    #[serde(rename = "shardsRoot")]
    pub shards_root: String,
    pub scope: VerifyScope,
    pub mode: VerifyMode,
    #[serde(rename = "sampleRate")]
    pub sample_rate: f64,
    #[serde(rename = "scannedShards")]
    pub scanned_shards: u64,
    #[serde(rename = "failedShards")]
    pub failed_shards: u64,
    pub shards: Vec<VerifyStoreShardReport>,
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

fn parse_manifest_epoch(path: &Path) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let bytes = std::fs::read(path)?;
    if bytes.len() < 24 {
        return Err(format!("manifest header too short: {}", path.display()).into());
    }
    let mut epoch = [0u8; 8];
    epoch.copy_from_slice(&bytes[16..24]);
    Ok(u64::from_le_bytes(epoch))
}

fn sampled_in(mode: VerifyMode, sample_rate: f64, shard_id: u32) -> bool {
    if matches!(mode, VerifyMode::Full) {
        return true;
    }
    if sample_rate >= 1.0 {
        return true;
    }
    if sample_rate <= 0.0 {
        return false;
    }
    let digest = blake3::hash(&shard_id.to_le_bytes());
    let mut u = [0u8; 8];
    u.copy_from_slice(&digest.as_bytes()[..8]);
    let x = u64::from_le_bytes(u);
    let p = (x as f64) / (u64::MAX as f64);
    p < sample_rate
}

fn classify_corruption_reason(err: &str) -> String {
    let lower = err.to_ascii_lowercase();
    if lower.contains("trailer") && lower.contains("hash") {
        return "TRAILER_HASH_MISMATCH".to_string();
    }
    if lower.contains("toc") && (lower.contains("checksum") || lower.contains("crc")) {
        return "TOC_CHECKSUM_MISMATCH".to_string();
    }
    if lower.contains("headerhash") || (lower.contains("header") && lower.contains("hash")) {
        return "FRAME_HEADER_HASH_MISMATCH".to_string();
    }
    if lower.contains("payloadhash") || (lower.contains("payload") && lower.contains("hash")) {
        return "FRAME_PAYLOAD_HASH_MISMATCH".to_string();
    }
    if lower.contains("invalid toc") {
        return "INVALID_TOC".to_string();
    }
    if lower.contains("invalid frame") || lower.contains("frame count mismatch") {
        return "INVALID_FRAME".to_string();
    }
    if lower.contains("io") || lower.contains("no such file") || lower.contains("permission") {
        return "IO_READ_FAILED".to_string();
    }
    "INTERNAL".to_string()
}

fn open_storage_for_shard(
    shard_root: &Path,
    shard_id: u32,
    epoch: u64,
    _device_index: i32,
) -> Result<ShardStorage, Box<dyn std::error::Error + Send + Sync>> {
    Ok(ShardStorage::open(
        shard_root,
        shard_id,
        epoch,
        ShardStorageOptions::default(),
    )?)
}

pub fn verify_store(opts: &VerifyStoreOptions) -> Result<VerifyStoreReport, Box<dyn std::error::Error + Send + Sync>> {
    let shard_root = opts.data_dir.join("shards");
    let mut shard_ids = if let Some(sid) = opts.shard {
        vec![sid]
    } else {
        list_shards(&shard_root)?
    };
    if matches!(opts.scope, VerifyScope::Recent) && opts.shard.is_none() && shard_ids.len() > 2 {
        shard_ids = shard_ids[shard_ids.len() - 2..].to_vec();
    }

    let mut out: Vec<VerifyStoreShardReport> = Vec::new();
    let mut failed = 0u64;
    let mut scanned = 0u64;

    for shard_id in shard_ids {
        let include = sampled_in(opts.mode, opts.sample_rate, shard_id);
        let manifest = shard_root.join(format!("shard-{shard_id:04}")).join("MANIFEST");
        let epoch = match parse_manifest_epoch(&manifest) {
            Ok(v) => v,
            Err(err) => {
                failed = failed.saturating_add(1);
                out.push(VerifyStoreShardReport {
                    shard_id,
                    epoch: 0,
                    scanned: false,
                    ok: false,
                    reason: Some("MANIFEST_READ_FAILED".to_string()),
                    error: Some(err.to_string()),
                    elapsed_ms: 0,
                    stats: None,
                });
                continue;
            }
        };

        if !include {
            out.push(VerifyStoreShardReport {
                shard_id,
                epoch,
                scanned: false,
                ok: true,
                reason: None,
                error: None,
                elapsed_ms: 0,
                stats: None,
            });
            continue;
        }

        scanned = scanned.saturating_add(1);
        let started = Instant::now();
        let storage = open_storage_for_shard(&shard_root, shard_id, epoch, opts.device_index);
        match storage {
            Ok(storage) => match storage.integrity_scan_stats_all(opts.budget_bytes) {
                Ok(stats) => {
                    out.push(VerifyStoreShardReport {
                        shard_id,
                        epoch,
                        scanned: true,
                        ok: true,
                        reason: None,
                        error: None,
                        elapsed_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                        stats: Some(stats.into()),
                    });
                }
                Err(err) => {
                    failed = failed.saturating_add(1);
                    let es = err.to_string();
                    out.push(VerifyStoreShardReport {
                        shard_id,
                        epoch,
                        scanned: true,
                        ok: false,
                        reason: Some(classify_corruption_reason(&es)),
                        error: Some(es),
                        elapsed_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                        stats: None,
                    });
                }
            },
            Err(err) => {
                failed = failed.saturating_add(1);
                let es = err.to_string();
                out.push(VerifyStoreShardReport {
                    shard_id,
                    epoch,
                    scanned: true,
                    ok: false,
                    reason: Some(classify_corruption_reason(&es)),
                    error: Some(es),
                    elapsed_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                    stats: None,
                });
            }
        }
    }

    Ok(VerifyStoreReport {
        ok: failed == 0,
        data_dir: opts.data_dir.display().to_string(),
        shards_root: shard_root.display().to_string(),
        scope: opts.scope,
        mode: opts.mode,
        sample_rate: opts.sample_rate,
        scanned_shards: scanned,
        failed_shards: failed,
        shards: out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ── VerifyScope ──────────────────────────────────────────────────

    #[test]
    fn verify_scope_parse_valid() {
        assert_eq!(VerifyScope::parse("recent"), Some(VerifyScope::Recent));
        assert_eq!(VerifyScope::parse("all"), Some(VerifyScope::All));
    }

    #[test]
    fn verify_scope_parse_case_insensitive() {
        assert_eq!(VerifyScope::parse("RECENT"), Some(VerifyScope::Recent));
        assert_eq!(VerifyScope::parse("  All  "), Some(VerifyScope::All));
    }

    #[test]
    fn verify_scope_parse_invalid() {
        assert_eq!(VerifyScope::parse(""), None);
        assert_eq!(VerifyScope::parse("partial"), None);
    }

    // ── VerifyMode ───────────────────────────────────────────────────

    #[test]
    fn verify_mode_parse_valid() {
        assert_eq!(VerifyMode::parse("sampled"), Some(VerifyMode::Sampled));
        assert_eq!(VerifyMode::parse("full"), Some(VerifyMode::Full));
    }

    #[test]
    fn verify_mode_parse_case_insensitive() {
        assert_eq!(VerifyMode::parse("  FULL  "), Some(VerifyMode::Full));
    }

    #[test]
    fn verify_mode_parse_invalid() {
        assert_eq!(VerifyMode::parse("quick"), None);
    }

    // ── sampled_in ───────────────────────────────────────────────────

    #[test]
    fn sampled_in_full_mode_always_true() {
        for shard_id in 0..10 {
            assert!(sampled_in(VerifyMode::Full, 0.0, shard_id));
        }
    }

    #[test]
    fn sampled_in_rate_1_always_true() {
        for shard_id in 0..10 {
            assert!(sampled_in(VerifyMode::Sampled, 1.0, shard_id));
        }
    }

    #[test]
    fn sampled_in_rate_0_always_false() {
        for shard_id in 0..10 {
            assert!(!sampled_in(VerifyMode::Sampled, 0.0, shard_id));
        }
    }

    #[test]
    fn sampled_in_deterministic() {
        // Same shard_id + rate should always produce the same result
        let a = sampled_in(VerifyMode::Sampled, 0.5, 42);
        let b = sampled_in(VerifyMode::Sampled, 0.5, 42);
        assert_eq!(a, b);
    }

    #[test]
    fn sampled_in_half_rate_filters_some() {
        let mut included = 0;
        let total = 1000;
        for shard_id in 0..total {
            if sampled_in(VerifyMode::Sampled, 0.5, shard_id) {
                included += 1;
            }
        }
        // With 50% sampling over 1000 shards, we expect roughly 500
        assert!(included > 300 && included < 700, "included = {included}");
    }

    // ── classify_corruption_reason ───────────────────────────────────

    #[test]
    fn classify_trailer_hash() {
        assert_eq!(
            classify_corruption_reason("trailer hash mismatch at offset 1024"),
            "TRAILER_HASH_MISMATCH"
        );
    }

    #[test]
    fn classify_toc_checksum() {
        assert_eq!(
            classify_corruption_reason("TOC checksum failed"),
            "TOC_CHECKSUM_MISMATCH"
        );
        assert_eq!(classify_corruption_reason("toc crc mismatch"), "TOC_CHECKSUM_MISMATCH");
    }

    #[test]
    fn classify_frame_header_hash() {
        assert_eq!(
            classify_corruption_reason("HeaderHash mismatch"),
            "FRAME_HEADER_HASH_MISMATCH"
        );
        assert_eq!(
            classify_corruption_reason("frame header hash error"),
            "FRAME_HEADER_HASH_MISMATCH"
        );
    }

    #[test]
    fn classify_payload_hash() {
        assert_eq!(
            classify_corruption_reason("PayloadHash verification failed"),
            "FRAME_PAYLOAD_HASH_MISMATCH"
        );
    }

    #[test]
    fn classify_invalid_toc() {
        assert_eq!(classify_corruption_reason("invalid toc entry"), "INVALID_TOC");
    }

    #[test]
    fn classify_invalid_frame() {
        assert_eq!(classify_corruption_reason("invalid frame at offset 0"), "INVALID_FRAME");
        assert_eq!(classify_corruption_reason("frame count mismatch"), "INVALID_FRAME");
    }

    #[test]
    fn classify_io_error() {
        assert_eq!(classify_corruption_reason("IO error: broken pipe"), "IO_READ_FAILED");
        assert_eq!(
            classify_corruption_reason("no such file or directory"),
            "IO_READ_FAILED"
        );
        assert_eq!(classify_corruption_reason("permission denied"), "IO_READ_FAILED");
    }

    #[test]
    fn classify_unknown_falls_through_to_internal() {
        assert_eq!(
            classify_corruption_reason("something completely unexpected"),
            "INTERNAL"
        );
    }

    // ── list_shards ──────────────────────────────────────────────────

    #[test]
    fn list_shards_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let ids = list_shards(tmp.path()).unwrap();
        assert!(ids.is_empty());
    }

    #[test]
    fn list_shards_finds_shard_dirs() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("shard-0000")).unwrap();
        fs::create_dir(tmp.path().join("shard-0003")).unwrap();
        fs::create_dir(tmp.path().join("shard-0001")).unwrap();
        // Non-shard entries should be ignored
        fs::create_dir(tmp.path().join("not-a-shard")).unwrap();
        fs::write(tmp.path().join("shard-file"), b"not a dir").unwrap();

        let ids = list_shards(tmp.path()).unwrap();
        assert_eq!(ids, vec![0, 1, 3]);
    }

    #[test]
    fn list_shards_deduplicates() {
        let tmp = TempDir::new().unwrap();
        // Can't actually have duplicate dirs, but verify sort+dedup path
        fs::create_dir(tmp.path().join("shard-0005")).unwrap();
        let ids = list_shards(tmp.path()).unwrap();
        assert_eq!(ids, vec![5]);
    }

    // ── parse_manifest_epoch ─────────────────────────────────────────

    #[test]
    fn parse_manifest_epoch_valid() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("MANIFEST");
        let mut data = vec![0u8; 32];
        let epoch: u64 = 42;
        data[16..24].copy_from_slice(&epoch.to_le_bytes());
        fs::write(&path, &data).unwrap();

        let result = parse_manifest_epoch(&path).unwrap();
        assert_eq!(result, 42);
    }

    #[test]
    fn parse_manifest_epoch_too_short() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("MANIFEST");
        fs::write(&path, [0u8; 10]).unwrap();
        let result = parse_manifest_epoch(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    // ── VerifyStoreStats from ReplayScanStats ────────────────────────

    #[test]
    fn verify_store_stats_from_replay_scan_stats() {
        let replay = ReplayScanStats {
            total_segments: 5,
            total_blocks: 10,
            total_frames: 100,
            total_compressed_bytes: 2048,
            total_uncompressed_bytes: 4096,
        };
        let stats: VerifyStoreStats = replay.into();
        assert_eq!(stats.total_segments, 5);
        assert_eq!(stats.total_blocks, 10);
        assert_eq!(stats.total_frames, 100);
        assert_eq!(stats.total_compressed_bytes, 2048);
        assert_eq!(stats.total_uncompressed_bytes, 4096);
    }

    // ── VerifyStoreReport serialization ──────────────────────────────

    #[test]
    fn verify_store_report_serializes() {
        let report = VerifyStoreReport {
            ok: true,
            data_dir: "/data".to_string(),
            shards_root: "/data/shards".to_string(),
            scope: VerifyScope::All,
            mode: VerifyMode::Full,
            sample_rate: 1.0,
            scanned_shards: 2,
            failed_shards: 0,
            shards: vec![],
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["ok"], true);
        assert_eq!(json["dataDir"], "/data");
        assert_eq!(json["shardsRoot"], "/data/shards");
        assert_eq!(json["scope"], "all");
        assert_eq!(json["mode"], "full");
    }

    #[test]
    fn shard_report_omits_none_fields() {
        let report = VerifyStoreShardReport {
            shard_id: 0,
            epoch: 1,
            scanned: false,
            ok: true,
            reason: None,
            error: None,
            elapsed_ms: 0,
            stats: None,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("reason"));
        assert!(!json.contains("error"));
        assert!(!json.contains("stats"));
    }

    // ── verify_store with missing shards dir ─────────────────────────

    #[test]
    fn verify_store_missing_shard_root_errors() {
        let tmp = TempDir::new().unwrap();
        let opts = VerifyStoreOptions {
            data_dir: tmp.path().to_path_buf(),
            shard: None,
            scope: VerifyScope::All,
            mode: VerifyMode::Full,
            sample_rate: 1.0,
            budget_bytes: 1024 * 1024,
            device_index: 0,
        };
        // No "shards" dir => read_dir should fail
        let result = verify_store(&opts);
        assert!(result.is_err());
    }

    #[test]
    fn verify_store_empty_shard_root_ok() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("shards")).unwrap();
        let opts = VerifyStoreOptions {
            data_dir: tmp.path().to_path_buf(),
            shard: None,
            scope: VerifyScope::All,
            mode: VerifyMode::Full,
            sample_rate: 1.0,
            budget_bytes: 1024 * 1024,
            device_index: 0,
        };
        let report = verify_store(&opts).unwrap();
        assert!(report.ok);
        assert_eq!(report.scanned_shards, 0);
        assert_eq!(report.failed_shards, 0);
        assert!(report.shards.is_empty());
    }

    #[test]
    fn verify_store_bad_manifest_records_failure() {
        let tmp = TempDir::new().unwrap();
        let shard_dir = tmp.path().join("shards").join("shard-0000");
        fs::create_dir_all(&shard_dir).unwrap();
        // Write a too-short manifest
        fs::write(shard_dir.join("MANIFEST"), [0u8; 4]).unwrap();

        let opts = VerifyStoreOptions {
            data_dir: tmp.path().to_path_buf(),
            shard: None,
            scope: VerifyScope::All,
            mode: VerifyMode::Full,
            sample_rate: 1.0,
            budget_bytes: 1024 * 1024,
            device_index: 0,
        };
        let report = verify_store(&opts).unwrap();
        assert!(!report.ok);
        assert_eq!(report.failed_shards, 1);
        assert_eq!(report.shards.len(), 1);
        assert_eq!(report.shards[0].shard_id, 0);
        assert!(!report.shards[0].ok);
        assert_eq!(report.shards[0].reason.as_deref(), Some("MANIFEST_READ_FAILED"));
    }

    #[test]
    fn verify_store_specific_shard_with_bad_manifest() {
        let tmp = TempDir::new().unwrap();
        let shard_dir = tmp.path().join("shards").join("shard-0005");
        fs::create_dir_all(&shard_dir).unwrap();
        fs::write(shard_dir.join("MANIFEST"), [0u8; 2]).unwrap();

        let opts = VerifyStoreOptions {
            data_dir: tmp.path().to_path_buf(),
            shard: Some(5),
            scope: VerifyScope::All,
            mode: VerifyMode::Full,
            sample_rate: 1.0,
            budget_bytes: 1024 * 1024,
            device_index: 0,
        };
        let report = verify_store(&opts).unwrap();
        assert!(!report.ok);
        assert_eq!(report.failed_shards, 1);
        assert_eq!(report.shards[0].shard_id, 5);
    }

    #[test]
    fn verify_store_sampled_mode_skips_unsampled_shards() {
        let tmp = TempDir::new().unwrap();
        let shards_dir = tmp.path().join("shards");
        // Create many shards - some will be sampled, some not
        for i in 0..20 {
            let shard_dir = shards_dir.join(format!("shard-{i:04}"));
            fs::create_dir_all(&shard_dir).unwrap();
            let mut data = vec![0u8; 32];
            data[16..24].copy_from_slice(&(1u64).to_le_bytes());
            fs::write(shard_dir.join("MANIFEST"), &data).unwrap();
        }

        let opts = VerifyStoreOptions {
            data_dir: tmp.path().to_path_buf(),
            shard: None,
            scope: VerifyScope::All,
            mode: VerifyMode::Sampled,
            sample_rate: 0.0, // 0% sampling = skip all
            budget_bytes: 1024 * 1024,
            device_index: 0,
        };
        let report = verify_store(&opts).unwrap();
        assert!(report.ok);
        // All shards should be present but none scanned
        assert_eq!(report.scanned_shards, 0);
        assert!(report.shards.iter().all(|s| !s.scanned));
    }

    #[test]
    fn verify_store_scope_serializes_to_lowercase() {
        let json = serde_json::to_string(&VerifyScope::Recent).unwrap();
        assert_eq!(json, "\"recent\"");
        let json = serde_json::to_string(&VerifyScope::All).unwrap();
        assert_eq!(json, "\"all\"");
    }

    #[test]
    fn verify_mode_serializes_to_lowercase() {
        let json = serde_json::to_string(&VerifyMode::Sampled).unwrap();
        assert_eq!(json, "\"sampled\"");
        let json = serde_json::to_string(&VerifyMode::Full).unwrap();
        assert_eq!(json, "\"full\"");
    }

    #[test]
    fn shard_report_with_stats_serializes() {
        let report = VerifyStoreShardReport {
            shard_id: 1,
            epoch: 1,
            scanned: true,
            ok: true,
            reason: None,
            error: None,
            elapsed_ms: 42,
            stats: Some(VerifyStoreStats {
                total_segments: 5,
                total_blocks: 10,
                total_frames: 100,
                total_compressed_bytes: 2048,
                total_uncompressed_bytes: 4096,
            }),
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["elapsedMs"], 42);
        assert_eq!(json["stats"]["total_frames"], 100);
    }

    #[test]
    fn verify_store_recent_scope_limits_to_last_two() {
        let tmp = TempDir::new().unwrap();
        let shards_dir = tmp.path().join("shards");
        for i in 0..5 {
            let shard_dir = shards_dir.join(format!("shard-{i:04}"));
            fs::create_dir_all(&shard_dir).unwrap();
            // Write valid-length manifest (24+ bytes) with epoch = i
            let mut data = vec![0u8; 32];
            data[16..24].copy_from_slice(&(i as u64).to_le_bytes());
            fs::write(shard_dir.join("MANIFEST"), &data).unwrap();
        }

        let opts = VerifyStoreOptions {
            data_dir: tmp.path().to_path_buf(),
            shard: None,
            scope: VerifyScope::Recent,
            mode: VerifyMode::Full,
            sample_rate: 1.0,
            budget_bytes: 1024 * 1024,
            device_index: 0,
        };
        let report = verify_store(&opts).unwrap();
        // Recent scope with >2 shards should only include last 2
        assert_eq!(report.shards.len(), 2);
        assert_eq!(report.shards[0].shard_id, 3);
        assert_eq!(report.shards[1].shard_id, 4);
    }
}
