// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::ValueEnum;
use corecrux_segment::decode_segment_v1;
use corecrux_storage::load_manifest_segment_catalog;
use corecrux_types::{build_info, EvidenceNodeContextV1, SegmentOffloadedV1, EVT_SEGMENT_OFFLOADED_V1};
use serde::{Deserialize, Serialize};

use crate::ops::{append_ops_event, OpsAppendOptions, OpsAppendReceipt};
use crate::tooling_env::ToolingEnvironment;

type DynError = Box<dyn std::error::Error + Send + Sync>;

const DAY_NS: u64 = 86_400_000_000_000;
const OFFLOAD_INDEX_SCHEMA_V1: &str = "corecruxctl.storage.offload.index.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum StorageTier {
    Warm,
    Cold,
}

impl StorageTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warm => "warm",
            Self::Cold => "cold",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum OffloadTargetKind {
    Local,
    S3,
    Rsync,
}

impl OffloadTargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::S3 => "s3",
            Self::Rsync => "rsync",
        }
    }
}

#[derive(Debug, Clone)]
pub struct StorageOffloadOptions {
    pub data_dir: PathBuf,
    pub environment: ToolingEnvironment,
    pub tier: StorageTier,
    pub older_than_days: u32,
    pub target: String,
    pub target_kind: Option<OffloadTargetKind>,
    pub rsync_rsh: Option<String>,
    pub verify_after_copy: bool,
    pub allow_unverified_copy: bool,
    pub allow_missing_ops_evidence: bool,
    pub delete_source: bool,
    pub evidence_out: Option<PathBuf>,
    pub ops_grpc: Option<String>,
    pub ops_scopes: Option<String>,
    pub node_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StorageOffloadItem {
    #[serde(rename = "shardId")]
    pub shard_id: u32,
    pub epoch: u64,
    #[serde(rename = "segmentSeq")]
    pub segment_seq: u64,
    #[serde(rename = "segmentId")]
    pub segment_id: String,
    #[serde(rename = "relativePath")]
    pub relative_path: String,
    #[serde(rename = "sourcePath")]
    pub source_path: String,
    #[serde(rename = "targetPath")]
    pub target_path: String,
    #[serde(rename = "segmentHashBlake3")]
    pub segment_hash_blake3: String,
    #[serde(rename = "transferHashBlake3", skip_serializing_if = "Option::is_none")]
    pub transfer_hash_blake3: Option<String>,
    #[serde(rename = "ageDays")]
    pub age_days: u64,
    #[serde(rename = "bytesCopied")]
    pub bytes_copied: u64,
    pub copied: bool,
    pub verified: bool,
    #[serde(rename = "sourceDeleted")]
    pub source_deleted: bool,
    #[serde(rename = "alreadyOffloaded")]
    pub already_offloaded: bool,
    #[serde(rename = "indexWritten")]
    pub index_written: bool,
    #[serde(rename = "opsEvidenceOk", skip_serializing_if = "Option::is_none")]
    pub ops_evidence_ok: Option<bool>,
    #[serde(rename = "opsAppendReceipt", skip_serializing_if = "Option::is_none")]
    pub ops_append_receipt: Option<OpsAppendReceipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StorageOffloadReport {
    pub schema: String,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
    #[serde(rename = "dataDir")]
    pub data_dir: String,
    pub environment: String,
    pub tier: String,
    #[serde(rename = "targetKind")]
    pub target_kind: String,
    pub target: String,
    #[serde(rename = "olderThanDays")]
    pub older_than_days: u32,
    #[serde(rename = "verifyAfterCopy")]
    pub verify_after_copy: bool,
    #[serde(rename = "deleteSource")]
    pub delete_source: bool,
    pub offloaded: u64,
    #[serde(rename = "alreadyOffloaded")]
    pub already_offloaded: u64,
    pub skipped: u64,
    #[serde(rename = "bytesCopied")]
    pub bytes_copied: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    pub segments: Vec<StorageOffloadItem>,
}

#[derive(Debug, Clone)]
enum OffloadTarget {
    Local { root: PathBuf },
    S3 { prefix: String },
    Rsync { prefix: String, rsync_rsh: String },
}

impl OffloadTarget {
    fn kind(&self) -> OffloadTargetKind {
        match self {
            Self::Local { .. } => OffloadTargetKind::Local,
            Self::S3 { .. } => OffloadTargetKind::S3,
            Self::Rsync { .. } => OffloadTargetKind::Rsync,
        }
    }

    fn identity(&self) -> String {
        match self {
            Self::Local { root } => format!("local:{}", root.display()),
            Self::S3 { prefix } => format!("s3:{prefix}"),
            Self::Rsync { prefix, .. } => format!("rsync:{prefix}"),
        }
    }
}

#[derive(Debug, Clone)]
struct SourceInspection {
    file_len: u64,
    source_hash_blake3: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OffloadIndexFile {
    schema: String,
    tier: String,
    #[serde(rename = "shardId")]
    shard_id: u32,
    entries: Vec<OffloadIndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OffloadIndexEntry {
    key: String,
    #[serde(rename = "segmentSeq")]
    segment_seq: u64,
    #[serde(rename = "sourceHashBlake3")]
    source_hash_blake3: String,
    #[serde(rename = "targetDigest")]
    target_digest: String,
    #[serde(rename = "targetKind")]
    target_kind: String,
    #[serde(rename = "targetPath")]
    target_path: String,
    #[serde(rename = "indexedAt")]
    indexed_at: String,
}

#[derive(Debug, Clone)]
struct OffloadIndexState {
    shard_id: u32,
    tier: StorageTier,
    entries: BTreeMap<String, OffloadIndexEntry>,
}

pub fn offload_segments(opts: &StorageOffloadOptions) -> Result<StorageOffloadReport, DynError> {
    if opts.delete_source {
        return Err("--delete-source is disabled until a future retention project adds archive-aware reads or manifest-tiering semantics".into());
    }
    if opts.allow_unverified_copy && opts.environment != ToolingEnvironment::Local {
        return Err("--allow-unverified-copy is supported only in --environment local".into());
    }
    if opts.allow_missing_ops_evidence && opts.environment != ToolingEnvironment::Local {
        return Err("--allow-missing-ops-evidence is supported only in --environment local".into());
    }

    let verify_after_copy = if opts.allow_unverified_copy {
        opts.verify_after_copy
    } else {
        true
    };
    let ops_required = opts.environment.requires_ops_evidence();
    if ops_required && opts.ops_grpc.is_none() {
        return Err("--grpc is required when --environment is staging or production".into());
    }

    let target = parse_target(&opts.target, opts.target_kind, opts.rsync_rsh.as_deref())?;
    let target_digest = blake3_hex(
        format!(
            "{}:{}:{}",
            opts.tier.as_str(),
            target.kind().as_str(),
            target.identity()
        )
        .as_bytes(),
    );
    let mut segments = Vec::new();
    let mut warnings = Vec::new();
    let mut offloaded = 0u64;
    let mut already_offloaded = 0u64;
    let mut skipped = 0u64;
    let mut bytes_copied = 0u64;
    let now_ns = now_unix_ns();
    let cutoff_unix_ns = now_ns.saturating_sub((opts.older_than_days as u64) * DAY_NS);
    let ops = opts.ops_grpc.as_ref().map(|grpc| OpsAppendOptions {
        grpc: grpc.clone(),
        scopes: opts.ops_scopes.clone(),
        node_id: opts.node_id.clone().unwrap_or_else(default_node_id),
    });
    let node_context = build_node_context(ops.as_ref());
    let mut indexes = BTreeMap::new();
    let mut dirty_indexes = BTreeSet::new();

    for shard_id in list_shards(&opts.data_dir.join("shards"))? {
        let shard_dir = opts.data_dir.join("shards").join(format!("shard-{shard_id:04}"));
        let catalog = load_manifest_segment_catalog(&shard_dir)?;
        if let std::collections::btree_map::Entry::Vacant(e) = indexes.entry(shard_id) {
            e.insert(load_offload_index(&opts.data_dir, opts.tier, shard_id)?);
        }
        let index = indexes.get_mut(&shard_id).expect("index loaded");

        for segment in catalog.segments {
            let source_path = shard_dir.join(&segment.relative_path);
            let age_days = now_ns.saturating_sub(segment.sealed_at_unix_ns) / DAY_NS;
            let target_path = build_target_path(&target, shard_id, &segment.relative_path);
            let mut item = StorageOffloadItem {
                shard_id,
                epoch: segment.epoch,
                segment_seq: segment.segment_seq,
                segment_id: hex_bytes(&segment.segment_id.0),
                relative_path: segment.relative_path.clone(),
                source_path: source_path.display().to_string(),
                target_path: target_path.clone(),
                segment_hash_blake3: hex_bytes(&segment.segment_hash),
                transfer_hash_blake3: None,
                age_days,
                bytes_copied: 0,
                copied: false,
                verified: false,
                source_deleted: false,
                already_offloaded: false,
                index_written: false,
                ops_evidence_ok: None,
                ops_append_receipt: None,
                reason: None,
            };

            if segment.sealed_at_unix_ns > cutoff_unix_ns {
                item.reason = Some("TOO_RECENT".to_string());
                skipped = skipped.saturating_add(1);
                segments.push(item);
                continue;
            }

            let inspection = inspect_source_segment(&source_path, &segment.segment_hash)?;
            let index_key = build_index_key(segment.segment_seq, &inspection.source_hash_blake3, &target_digest);
            item.bytes_copied = inspection.file_len;
            item.transfer_hash_blake3 = Some(inspection.source_hash_blake3.clone());

            if index.entries.contains_key(&index_key) {
                item.already_offloaded = true;
                item.verified = true;
                item.reason = Some("ALREADY_OFFLOADED".to_string());
                already_offloaded = already_offloaded.saturating_add(1);
                skipped = skipped.saturating_add(1);
                segments.push(item);
                continue;
            }

            copy_to_target(&target, &source_path, &target_path)?;
            item.copied = true;

            if verify_after_copy {
                let verified_hash = verify_target_copy(&target, &target_path)?;
                if verified_hash != inspection.source_hash_blake3 {
                    return Err(format!(
                        "transfer hash mismatch for {} -> {}",
                        source_path.display(),
                        target_path
                    )
                    .into());
                }
                item.verified = true;
            } else {
                warnings.push(format!(
                    "segment {} on shard {shard_id} copied without destination verification",
                    segment.segment_seq
                ));
                item.reason = Some("UNVERIFIED_COPY".to_string());
            }

            if let Some(ops) = &ops {
                let event = SegmentOffloadedV1 {
                    schema: EVT_SEGMENT_OFFLOADED_V1.to_string(),
                    offloaded_at_unix_ms: now_unix_ms(),
                    tier: opts.tier.as_str().to_string(),
                    target: opts.target.clone(),
                    shard_id,
                    epoch: segment.epoch,
                    segment_seq: segment.segment_seq,
                    segment_id: item.segment_id.clone(),
                    segment_hash_blake3: item.segment_hash_blake3.clone(),
                    source_path: item.source_path.clone(),
                    target_path: item.target_path.clone(),
                    verified: item.verified,
                    source_deleted: item.source_deleted,
                    bytes_copied: item.bytes_copied,
                    node: node_context.clone(),
                };
                let event_id = build_segment_offloaded_event_id(
                    &ops.node_id,
                    shard_id,
                    segment.segment_seq,
                    &target_digest,
                    &inspection.source_hash_blake3,
                );
                match append_ops_event(ops, EVT_SEGMENT_OFFLOADED_V1, &event_id, &event) {
                    Ok(receipt) => {
                        item.ops_evidence_ok = Some(true);
                        item.ops_append_receipt = Some(receipt);
                    }
                    Err(err) => {
                        item.ops_evidence_ok = Some(false);
                        if ops_required {
                            return Err(format!(
                                "ops evidence append required for shard {shard_id} segment {}: {err}",
                                segment.segment_seq
                            )
                            .into());
                        }
                        warnings.push(format!(
                            "failed to append ops event for shard {shard_id} segment {}: {err}",
                            segment.segment_seq
                        ));
                    }
                }
            }

            if item.verified {
                index.entries.insert(
                    index_key,
                    OffloadIndexEntry {
                        key: build_index_key(segment.segment_seq, &inspection.source_hash_blake3, &target_digest),
                        segment_seq: segment.segment_seq,
                        source_hash_blake3: inspection.source_hash_blake3.clone(),
                        target_digest: target_digest.clone(),
                        target_kind: target.kind().as_str().to_string(),
                        target_path: target_path.clone(),
                        indexed_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    },
                );
                dirty_indexes.insert(shard_id);
                item.index_written = true;
            }

            offloaded = offloaded.saturating_add(1);
            bytes_copied = bytes_copied.saturating_add(item.bytes_copied);
            segments.push(item);
        }
    }

    for shard_id in dirty_indexes {
        if let Some(index) = indexes.get(&shard_id) {
            save_offload_index(&opts.data_dir, index)?;
        }
    }

    let report = StorageOffloadReport {
        schema: "corecruxctl.storage.offload.v1".to_string(),
        generated_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        data_dir: opts.data_dir.display().to_string(),
        environment: opts.environment.as_str().to_string(),
        tier: opts.tier.as_str().to_string(),
        target_kind: target.kind().as_str().to_string(),
        target: opts.target.clone(),
        older_than_days: opts.older_than_days,
        verify_after_copy,
        delete_source: false,
        offloaded,
        already_offloaded,
        skipped,
        bytes_copied,
        warnings,
        segments,
    };

    if let Some(path) = &opts.evidence_out {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_vec_pretty(&report)?)?;
    }

    Ok(report)
}

fn list_shards(shards_root: &Path) -> Result<Vec<u32>, DynError> {
    let mut shard_ids = Vec::new();
    for entry in std::fs::read_dir(shards_root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        let Some(rest) = name.strip_prefix("shard-") else {
            continue;
        };
        let Ok(shard_id) = rest.parse::<u32>() else {
            continue;
        };
        shard_ids.push(shard_id);
    }
    shard_ids.sort_unstable();
    shard_ids.dedup();
    Ok(shard_ids)
}

fn parse_target(
    raw: &str,
    target_kind: Option<OffloadTargetKind>,
    rsync_rsh: Option<&str>,
) -> Result<OffloadTarget, DynError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("target must not be empty".into());
    }

    let inferred_kind = if let Some(kind) = target_kind {
        kind
    } else if trimmed.starts_with("s3://") {
        OffloadTargetKind::S3
    } else {
        OffloadTargetKind::Local
    };

    match inferred_kind {
        OffloadTargetKind::Local => Ok(OffloadTarget::Local {
            root: PathBuf::from(trimmed),
        }),
        OffloadTargetKind::S3 => {
            if !trimmed.starts_with("s3://") {
                return Err("--target-kind s3 requires an s3:// target".into());
            }
            Ok(OffloadTarget::S3 {
                prefix: trimmed.to_string(),
            })
        }
        OffloadTargetKind::Rsync => {
            if !trimmed.contains(':') {
                return Err("--target-kind rsync requires a remote rsync target like host:/path".into());
            }
            Ok(OffloadTarget::Rsync {
                prefix: trimmed.to_string(),
                rsync_rsh: rsync_rsh.unwrap_or("ssh").to_string(),
            })
        }
    }
}

fn build_target_path(target: &OffloadTarget, shard_id: u32, relative_path: &str) -> String {
    let shard_relative = PathBuf::from(format!("shard-{shard_id:04}")).join(relative_path);
    match target {
        OffloadTarget::Local { root } => root.join(&shard_relative).display().to_string(),
        OffloadTarget::S3 { prefix } | OffloadTarget::Rsync { prefix, .. } => {
            let suffix = shard_relative.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
            format!("{}/{}", prefix.trim_end_matches('/'), suffix)
        }
    }
}

fn inspect_source_segment(path: &Path, manifest_segment_hash: &[u8; 32]) -> Result<SourceInspection, DynError> {
    let bytes = std::fs::read(path)?;
    let (_header, _toc, _entries, footer) = decode_segment_v1(&bytes)?;
    if &footer.segment_hash != manifest_segment_hash {
        return Err(format!("manifest hash mismatch for {}", path.display()).into());
    }
    Ok(SourceInspection {
        file_len: bytes.len() as u64,
        source_hash_blake3: hex_bytes(blake3::hash(&bytes).as_bytes()),
    })
}

fn copy_to_target(target: &OffloadTarget, source_path: &Path, target_path: &str) -> Result<(), DynError> {
    match target {
        OffloadTarget::Local { .. } => {
            let target_path = PathBuf::from(target_path);
            if let Some(parent) = target_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(source_path, &target_path)?;
            Ok(())
        }
        OffloadTarget::S3 { .. } => {
            let status = Command::new("aws")
                .args(["s3", "cp"])
                .arg(source_path)
                .arg(target_path)
                .status()?;
            if !status.success() {
                return Err(format!("aws s3 cp failed for {}", source_path.display()).into());
            }
            Ok(())
        }
        OffloadTarget::Rsync { rsync_rsh, .. } => {
            let status = Command::new("rsync")
                .args(["-a", "--mkpath", "-e", rsync_rsh])
                .arg(source_path)
                .arg(target_path)
                .status()?;
            if !status.success() {
                return Err(format!("rsync upload failed for {}", source_path.display()).into());
            }
            Ok(())
        }
    }
}

fn verify_target_copy(target: &OffloadTarget, target_path: &str) -> Result<String, DynError> {
    match target {
        OffloadTarget::Local { .. } => blake3_file_hex(Path::new(target_path)),
        OffloadTarget::S3 { .. } => {
            let temp_dir = tempfile::tempdir()?;
            let temp_path = temp_dir.path().join("segment.ccxseg");
            let status = Command::new("aws")
                .args(["s3", "cp"])
                .arg(target_path)
                .arg(&temp_path)
                .status()?;
            if !status.success() {
                return Err(format!("aws s3 cp verification download failed for {target_path}").into());
            }
            blake3_file_hex(&temp_path)
        }
        OffloadTarget::Rsync { rsync_rsh, .. } => {
            let temp_dir = tempfile::tempdir()?;
            let temp_path = temp_dir.path().join("segment.ccxseg");
            let status = Command::new("rsync")
                .args(["-a", "-e", rsync_rsh])
                .arg(target_path)
                .arg(&temp_path)
                .status()?;
            if !status.success() {
                return Err(format!("rsync verification download failed for {target_path}").into());
            }
            blake3_file_hex(&temp_path)
        }
    }
}

fn blake3_file_hex(path: &Path) -> Result<String, DynError> {
    let mut hasher = blake3::Hasher::new();
    let mut file = File::open(path)?;
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hex_bytes(hasher.finalize().as_bytes()))
}

fn offload_index_path(data_dir: &Path, tier: StorageTier, shard_id: u32) -> PathBuf {
    data_dir
        .join("meta")
        .join("offload")
        .join(tier.as_str())
        .join(format!("shard-{shard_id:04}.json"))
}

fn load_offload_index(data_dir: &Path, tier: StorageTier, shard_id: u32) -> Result<OffloadIndexState, DynError> {
    let path = offload_index_path(data_dir, tier, shard_id);
    if !path.exists() {
        return Ok(OffloadIndexState {
            shard_id,
            tier,
            entries: BTreeMap::new(),
        });
    }

    let bytes = std::fs::read(path)?;
    let file: OffloadIndexFile = serde_json::from_slice(&bytes)?;
    let mut entries = BTreeMap::new();
    for entry in file.entries {
        entries.insert(entry.key.clone(), entry);
    }
    Ok(OffloadIndexState {
        shard_id,
        tier,
        entries,
    })
}

fn save_offload_index(data_dir: &Path, index: &OffloadIndexState) -> Result<(), DynError> {
    let path = offload_index_path(data_dir, index.tier, index.shard_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = OffloadIndexFile {
        schema: OFFLOAD_INDEX_SCHEMA_V1.to_string(),
        tier: index.tier.as_str().to_string(),
        shard_id: index.shard_id,
        entries: index.entries.values().cloned().collect(),
    };
    std::fs::write(path, serde_json::to_vec_pretty(&file)?)?;
    Ok(())
}

fn build_index_key(segment_seq: u64, source_hash_blake3: &str, target_digest: &str) -> String {
    format!("{segment_seq}:{source_hash_blake3}:{target_digest}")
}

fn build_segment_offloaded_event_id(
    node_id: &str,
    shard_id: u32,
    segment_seq: u64,
    target_digest: &str,
    source_hash_blake3: &str,
) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}",
        EVT_SEGMENT_OFFLOADED_V1, node_id, shard_id, segment_seq, target_digest, source_hash_blake3
    )
}

fn default_node_id() -> String {
    std::env::var("CORECRUX_NODE_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|value| !value.trim().is_empty()))
        .unwrap_or_else(|| "unknown-node".to_string())
}

fn build_node_context(ops: Option<&OpsAppendOptions>) -> EvidenceNodeContextV1 {
    EvidenceNodeContextV1 {
        node_id: ops.map(|value| value.node_id.clone()).unwrap_or_else(default_node_id),
        build: build_info(),
        http_listen_addr: None,
        grpc_listen_addr: ops.map(|value| value.grpc.clone()),
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

fn blake3_hex(bytes: &[u8]) -> String {
    hex_bytes(blake3::hash(bytes).as_bytes())
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        build_segment_offloaded_event_id, build_target_path, offload_index_path, offload_segments, parse_target,
        OffloadTarget, OffloadTargetKind, StorageOffloadItem, StorageOffloadOptions, StorageOffloadReport, StorageTier,
    };
    use crate::tooling_env::ToolingEnvironment;
    use corecrux_segment::decode_segment_v1;
    use corecrux_storage::{
        encode_manifest_add_segment_v1, encode_manifest_header_v1, frame_manifest_record, SegmentMeta,
    };
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    #[test]
    fn storage_tier_as_str() {
        assert_eq!(StorageTier::Warm.as_str(), "warm");
        assert_eq!(StorageTier::Cold.as_str(), "cold");
    }

    #[test]
    fn offload_target_kind_as_str() {
        assert_eq!(OffloadTargetKind::Local.as_str(), "local");
        assert_eq!(OffloadTargetKind::S3.as_str(), "s3");
        assert_eq!(OffloadTargetKind::Rsync.as_str(), "rsync");
    }

    #[test]
    fn offload_target_kind_identity() {
        let local = OffloadTarget::Local {
            root: PathBuf::from("/archive"),
        };
        assert_eq!(local.kind(), OffloadTargetKind::Local);
        assert_eq!(local.identity(), "local:/archive");

        let s3 = OffloadTarget::S3 {
            prefix: "s3://bucket/prefix".to_string(),
        };
        assert_eq!(s3.kind(), OffloadTargetKind::S3);
        assert_eq!(s3.identity(), "s3:s3://bucket/prefix");

        let rsync = OffloadTarget::Rsync {
            prefix: "host:/path".to_string(),
            rsync_rsh: "ssh".to_string(),
        };
        assert_eq!(rsync.kind(), OffloadTargetKind::Rsync);
        assert_eq!(rsync.identity(), "rsync:host:/path");
    }

    #[test]
    fn parse_target_infers_s3_from_prefix() {
        let target = parse_target("s3://bucket/prefix", None, None).expect("parse");
        assert!(matches!(target, OffloadTarget::S3 { .. }));
    }

    #[test]
    fn parse_target_defaults_to_local() {
        let target = parse_target("/archive/path", None, None).expect("parse");
        assert!(matches!(target, OffloadTarget::Local { .. }));
    }

    #[test]
    fn parse_target_empty_fails() {
        let result = parse_target("", None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must not be empty"));
    }

    #[test]
    fn parse_target_s3_without_prefix_fails() {
        let result = parse_target("/local/path", Some(OffloadTargetKind::S3), None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("s3://"));
    }

    #[test]
    fn parse_target_rsync_without_colon_fails() {
        let result = parse_target("/no/colon", Some(OffloadTargetKind::Rsync), None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("host:/path"));
    }

    #[test]
    fn parse_target_rsync_uses_default_rsh() {
        let target = parse_target("host:/path", Some(OffloadTargetKind::Rsync), None).expect("parse");
        match target {
            OffloadTarget::Rsync { rsync_rsh, .. } => assert_eq!(rsync_rsh, "ssh"),
            _ => panic!("expected rsync target"),
        }
    }

    #[test]
    fn parse_target_rsync_custom_rsh() {
        let target = parse_target("host:/path", Some(OffloadTargetKind::Rsync), Some("ssh -p 2222")).expect("parse");
        match target {
            OffloadTarget::Rsync { rsync_rsh, .. } => assert_eq!(rsync_rsh, "ssh -p 2222"),
            _ => panic!("expected rsync target"),
        }
    }

    #[test]
    fn build_index_key_format() {
        let key = super::build_index_key(42, "source_hash", "target_digest");
        assert_eq!(key, "42:source_hash:target_digest");
    }

    #[test]
    fn offload_index_path_structure() {
        let path = offload_index_path(Path::new("/data"), StorageTier::Warm, 7);
        assert_eq!(path, PathBuf::from("/data/meta/offload/warm/shard-0007.json"));
        let path_cold = offload_index_path(Path::new("/data"), StorageTier::Cold, 1);
        assert_eq!(path_cold, PathBuf::from("/data/meta/offload/cold/shard-0001.json"));
    }

    #[test]
    fn hex_bytes_produces_lowercase_hex() {
        assert_eq!(super::hex_bytes(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(super::hex_bytes(&[0x00, 0xff]), "00ff");
        assert_eq!(super::hex_bytes(&[]), "");
    }

    #[test]
    fn blake3_hex_is_deterministic() {
        let h1 = super::blake3_hex(b"test");
        let h2 = super::blake3_hex(b"test");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn offload_report_serializes() {
        let report = StorageOffloadReport {
            schema: "corecruxctl.storage.offload.v1".to_string(),
            generated_at: "2026-01-01T00:00:00Z".to_string(),
            data_dir: "/data".to_string(),
            environment: "local".to_string(),
            tier: "warm".to_string(),
            target_kind: "local".to_string(),
            target: "/archive".to_string(),
            older_than_days: 30,
            verify_after_copy: true,
            delete_source: false,
            offloaded: 5,
            already_offloaded: 2,
            skipped: 1,
            bytes_copied: 1024,
            warnings: Vec::new(),
            segments: Vec::new(),
        };
        let json = serde_json::to_value(&report).expect("serialize");
        assert_eq!(json["offloaded"], 5);
        assert_eq!(json["alreadyOffloaded"], 2);
        assert_eq!(json["tier"], "warm");
    }

    #[test]
    fn offload_item_serializes_with_optional_fields() {
        let item = StorageOffloadItem {
            shard_id: 1,
            epoch: 1,
            segment_seq: 42,
            segment_id: "id".to_string(),
            relative_path: "segments/seg.ccxseg".to_string(),
            source_path: "/data/shards/shard-0001/segments/seg.ccxseg".to_string(),
            target_path: "/archive/shard-0001/segments/seg.ccxseg".to_string(),
            segment_hash_blake3: "hash".to_string(),
            transfer_hash_blake3: None,
            age_days: 45,
            bytes_copied: 0,
            copied: false,
            verified: false,
            source_deleted: false,
            already_offloaded: false,
            index_written: false,
            ops_evidence_ok: None,
            ops_append_receipt: None,
            reason: Some("TOO_RECENT".to_string()),
        };
        let json = serde_json::to_string(&item).expect("serialize");
        assert!(!json.contains("transferHashBlake3"));
        assert!(!json.contains("opsEvidenceOk"));
        assert!(json.contains("\"reason\":\"TOO_RECENT\""));
    }

    #[test]
    fn allow_missing_ops_evidence_is_local_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = offload_segments(&StorageOffloadOptions {
            data_dir: dir.path().to_path_buf(),
            environment: ToolingEnvironment::Staging,
            tier: StorageTier::Warm,
            older_than_days: 0,
            target: dir.path().join("archive").display().to_string(),
            target_kind: Some(OffloadTargetKind::Local),
            rsync_rsh: None,
            verify_after_copy: false,
            allow_unverified_copy: false,
            allow_missing_ops_evidence: true,
            delete_source: false,
            evidence_out: None,
            ops_grpc: Some("http://127.0.0.1:4007".to_string()),
            ops_scopes: None,
            node_id: None,
        })
        .expect_err("should fail");
        assert!(err.to_string().contains("--allow-missing-ops-evidence"));
    }

    #[test]
    fn build_target_path_preserves_shard_layout_for_all_target_kinds() {
        let local = OffloadTarget::Local {
            root: PathBuf::from("/archive"),
        };
        assert_eq!(
            build_target_path(&local, 7, "segments/seg-1.ccxseg"),
            "/archive/shard-0007/segments/seg-1.ccxseg"
        );

        let s3 = OffloadTarget::S3 {
            prefix: "s3://bucket/prefix".to_string(),
        };
        assert_eq!(
            build_target_path(&s3, 7, "segments/seg-1.ccxseg"),
            "s3://bucket/prefix/shard-0007/segments/seg-1.ccxseg"
        );

        let rsync = OffloadTarget::Rsync {
            prefix: "archive-host:/srv/corecrux".to_string(),
            rsync_rsh: "ssh".to_string(),
        };
        assert_eq!(
            build_target_path(&rsync, 7, "segments/seg-1.ccxseg"),
            "archive-host:/srv/corecrux/shard-0007/segments/seg-1.ccxseg"
        );
    }

    #[test]
    fn parse_target_supports_explicit_rsync_kind() {
        let target = parse_target("archive-host:/srv/corecrux", Some(OffloadTargetKind::Rsync), None)
            .expect("parse rsync target");
        assert!(matches!(target, OffloadTarget::Rsync { .. }));
    }

    #[test]
    fn segment_offload_event_id_changes_with_target_digest() {
        let a = build_segment_offloaded_event_id("node-a", 7, 44, "target-a", "source");
        let b = build_segment_offloaded_event_id("node-a", 7, 44, "target-b", "source");
        assert_ne!(a, b);
    }

    #[test]
    fn delete_source_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = offload_segments(&StorageOffloadOptions {
            data_dir: dir.path().to_path_buf(),
            environment: ToolingEnvironment::Local,
            tier: StorageTier::Warm,
            older_than_days: 0,
            target: dir.path().join("archive").display().to_string(),
            target_kind: Some(OffloadTargetKind::Local),
            rsync_rsh: None,
            verify_after_copy: false,
            allow_unverified_copy: false,
            allow_missing_ops_evidence: false,
            delete_source: true,
            evidence_out: None,
            ops_grpc: None,
            ops_scopes: None,
            node_id: None,
        })
        .expect_err("delete-source should fail");
        assert!(err.to_string().contains("--delete-source is disabled"));
    }

    #[test]
    fn staging_offload_requires_ops_evidence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = offload_segments(&StorageOffloadOptions {
            data_dir: dir.path().to_path_buf(),
            environment: ToolingEnvironment::Staging,
            tier: StorageTier::Warm,
            older_than_days: 0,
            target: dir.path().join("archive").display().to_string(),
            target_kind: Some(OffloadTargetKind::Local),
            rsync_rsh: None,
            verify_after_copy: false,
            allow_unverified_copy: false,
            allow_missing_ops_evidence: false,
            delete_source: false,
            evidence_out: None,
            ops_grpc: None,
            ops_scopes: None,
            node_id: None,
        })
        .expect_err("staging without grpc should fail");
        assert!(err.to_string().contains("--grpc is required"));
    }

    #[test]
    fn unverified_copy_flag_is_local_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = offload_segments(&StorageOffloadOptions {
            data_dir: dir.path().to_path_buf(),
            environment: ToolingEnvironment::Staging,
            tier: StorageTier::Warm,
            older_than_days: 0,
            target: dir.path().join("archive").display().to_string(),
            target_kind: Some(OffloadTargetKind::Local),
            rsync_rsh: None,
            verify_after_copy: false,
            allow_unverified_copy: true,
            allow_missing_ops_evidence: false,
            delete_source: false,
            evidence_out: None,
            ops_grpc: Some("http://127.0.0.1:4007".to_string()),
            ops_scopes: None,
            node_id: None,
        })
        .expect_err("non-local unverified copy should fail");
        assert!(err.to_string().contains("--allow-unverified-copy"));
    }

    #[test]
    fn local_offload_rerun_skips_previously_indexed_segment() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        seed_manifest_backed_fixture(root);
        let archive = tempfile::tempdir().expect("archive");

        let opts = StorageOffloadOptions {
            data_dir: root.to_path_buf(),
            environment: ToolingEnvironment::Local,
            tier: StorageTier::Warm,
            older_than_days: 0,
            target: archive.path().display().to_string(),
            target_kind: Some(OffloadTargetKind::Local),
            rsync_rsh: None,
            verify_after_copy: false,
            allow_unverified_copy: false,
            allow_missing_ops_evidence: false,
            delete_source: false,
            evidence_out: None,
            ops_grpc: None,
            ops_scopes: None,
            node_id: None,
        };

        let first = offload_segments(&opts).expect("first offload");
        assert_eq!(first.offloaded, 1);
        assert_eq!(first.already_offloaded, 0);
        assert!(first.segments[0].copied);
        assert!(first.segments[0].verified);
        assert!(first.segments[0].index_written);

        let second = offload_segments(&opts).expect("second offload");
        assert_eq!(second.offloaded, 0);
        assert_eq!(second.already_offloaded, 1);
        assert!(second.segments[0].already_offloaded);
        assert!(!second.segments[0].copied);
        assert!(!second.segments[0].index_written);

        let index_path = offload_index_path(root, StorageTier::Warm, second.segments[0].shard_id);
        assert!(index_path.exists());
    }

    // ── default_node_id ───────────────────────────────────────────────

    #[test]
    fn default_node_id_falls_back_to_unknown() {
        // This test relies on CORECRUX_NODE_ID and HOSTNAME possibly being set.
        // It should always return a non-empty string.
        let id = super::default_node_id();
        assert!(!id.is_empty());
    }

    // ── build_node_context ──────────────────────────────────────────

    #[test]
    fn build_node_context_with_ops() {
        let ops = super::OpsAppendOptions {
            grpc: "http://localhost:4007".to_string(),
            scopes: None,
            node_id: "test-node".to_string(),
        };
        let ctx = super::build_node_context(Some(&ops));
        assert_eq!(ctx.node_id, "test-node");
        assert_eq!(ctx.grpc_listen_addr.as_deref(), Some("http://localhost:4007"));
        assert!(ctx.http_listen_addr.is_none());
    }

    #[test]
    fn build_node_context_without_ops() {
        let ctx = super::build_node_context(None);
        assert!(!ctx.node_id.is_empty());
        assert!(ctx.grpc_listen_addr.is_none());
        assert!(ctx.http_listen_addr.is_none());
    }

    // ── now_unix_ms / now_unix_ns ───────────────────────────────────

    #[test]
    fn now_unix_ms_plausible() {
        let ms = super::now_unix_ms();
        assert!(ms > 1_577_836_800_000); // 2020-01-01
    }

    #[test]
    fn now_unix_ns_plausible() {
        let ns = super::now_unix_ns();
        assert!(ns > 1_577_836_800_000_000_000); // 2020-01-01
    }

    // ── offload_index round-trip ────────────────────────────────────

    #[test]
    fn offload_index_save_load_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let idx = super::OffloadIndexState {
            shard_id: 5,
            tier: StorageTier::Cold,
            entries: std::collections::BTreeMap::from([(
                "key1".to_string(),
                super::OffloadIndexEntry {
                    key: "key1".to_string(),
                    segment_seq: 42,
                    source_hash_blake3: "deadbeef".to_string(),
                    target_digest: "digest".to_string(),
                    target_kind: "local".to_string(),
                    target_path: "/archive/seg".to_string(),
                    indexed_at: "2026-01-01T00:00:00Z".to_string(),
                },
            )]),
        };
        super::save_offload_index(dir.path(), &idx).expect("save");
        let loaded = super::load_offload_index(dir.path(), StorageTier::Cold, 5).expect("load");
        assert_eq!(loaded.shard_id, 5);
        assert_eq!(loaded.entries.len(), 1);
        assert!(loaded.entries.contains_key("key1"));
    }

    // ── blake3_file_hex ─────────────────────────────────────────────

    #[test]
    fn blake3_file_hex_produces_deterministic_hex() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.bin");
        std::fs::write(&path, b"hello world").expect("write");
        let h1 = super::blake3_file_hex(&path).expect("hash");
        let h2 = super::blake3_file_hex(&path).expect("hash");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    fn seed_manifest_backed_fixture(root: &Path) {
        let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures_segments/minimal");
        let fixture_seg = fixture_dir.join("minimal.ccxseg");
        let seg_bytes = std::fs::read(&fixture_seg).expect("read fixture segment");
        let (_h, _toc_h, _entries, footer) = decode_segment_v1(&seg_bytes).expect("decode segment");

        let shard_dir = root.join("shards").join(format!("shard-{:04}", footer.shard_id));
        std::fs::create_dir_all(shard_dir.join("segments")).expect("create shard segments dir");

        let rel = "segments/minimal.ccxseg";
        let dst = shard_dir.join(rel);
        std::fs::copy(&fixture_seg, &dst).expect("copy fixture segment");

        let manifest_path = shard_dir.join("MANIFEST");
        let mut manifest = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&manifest_path)
            .expect("create MANIFEST");
        let header = encode_manifest_header_v1(footer.shard_id, footer.epoch, 123).expect("manifest header");
        manifest.write_all(&header).expect("write manifest header");

        let segment = SegmentMeta {
            level: 0,
            shard_id: footer.shard_id,
            epoch: footer.epoch,
            segment_seq: footer.segment_seq,
            segment_id: footer.segment_id,
            relative_path: rel.to_string(),
            file_len: footer.file_len,
            created_at_unix_ns: footer.created_at_unix_ns,
            sealed_at_unix_ns: footer.sealed_at_unix_ns,
            toc_offset: footer.toc_offset,
            toc_len: footer.toc_len,
            toc_entry_count: footer.toc_entry_count,
            min_stream_hash: footer.min_stream_hash,
            min_seq: footer.min_seq,
            max_stream_hash: footer.max_stream_hash,
            max_seq: footer.max_seq,
            segment_hash: footer.segment_hash,
        };
        let record = encode_manifest_add_segment_v1(&segment).expect("encode manifest add segment");
        let framed = frame_manifest_record(&record);
        manifest.write_all(&framed).expect("write manifest record");
        manifest.sync_all().expect("sync manifest");
    }
}
