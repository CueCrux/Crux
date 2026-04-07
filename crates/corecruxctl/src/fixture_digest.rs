// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use corecrux_frame::{compute_header_hash, compute_payload_hash};
use corecrux_segment::decode_frame_v1;
use corecrux_storage::{
    encode_manifest_add_segment_v1, encode_manifest_header_v1, frame_manifest_record, SegmentMeta, ShardPaths,
    ShardStorage, ShardStorageOptions,
};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, serde::Serialize)]
pub struct FixtureDigestReport {
    pub fixture: String,
    pub shard_id: u32,
    pub epoch: u64,
    pub segment_seq: u64,
    pub cuda_enabled: bool,
    pub cuda_driver_version: Option<String>,
    pub device_index: i32,
    pub device_name: Option<String>,
    pub total_frames: u64,
    pub digest_blake3: String,
}

fn repo_root() -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize()?)
}

pub fn fixture_segment_path(fixture: &str) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let root = repo_root()?;
    Ok(root
        .join("tests/fixtures_segments")
        .join(fixture)
        .join(format!("{fixture}.ccxseg")))
}

#[allow(clippy::unwrap_used, clippy::expect_used)] // Diagnostic function: panics on corrupt sealed-segment frames (by design)
fn replay_digest(frames: &[(corecrux_storage::FrameLocation, Vec<u8>)]) -> (u64, String) {
    let mut hasher = blake3::Hasher::new();
    for (loc, frame) in frames {
        let decoded = decode_frame_v1(frame).expect("decode frame");
        assert!(
            (decoded.header_bytes.len() >= 32),
            "stored frame header_bytes too small"
        );
        let canonical_len = decoded.header_bytes.len() - 32;
        let canonical_bytes = &decoded.header_bytes[..canonical_len];
        let header_hash = compute_header_hash(canonical_bytes);
        let payload_hash = compute_payload_hash(&decoded.payload_bytes);

        hasher.update(&header_hash);
        hasher.update(&payload_hash);
        hasher.update(&loc.shard_id.to_le_bytes());
        hasher.update(&loc.segment_seq.to_le_bytes());
        hasher.update(&loc.offset.to_le_bytes());
    }
    (frames.len() as u64, hasher.finalize().to_hex().to_string())
}

pub fn segment_replay_digest_from_segment_path(
    segment_path: &std::path::Path,
    device_index: i32,
) -> Result<FixtureDigestReport, Box<dyn std::error::Error + Send + Sync>> {
    let fixture_seg = segment_path.to_path_buf();
    if !fixture_seg.exists() {
        return Err(format!("fixture segment not found: {}", fixture_seg.display()).into());
    }

    let seg_bytes = std::fs::read(&fixture_seg)?;
    let (_h, _toc_h, _entries, footer) = corecrux_segment::decode_segment_v1(&seg_bytes)?;
    let fixture_name = fixture_seg
        .file_stem()
        .map_or_else(|| "fixture".to_string(), |v| v.to_string_lossy().to_string());

    let dir = tempfile::tempdir()?;
    let root = dir.path();

    let shard_id = footer.shard_id;
    let epoch = footer.epoch;
    let paths = ShardPaths::for_root(root, shard_id);
    std::fs::create_dir_all(&paths.segments_dir)?;

    let rel = format!("segments/{fixture_name}.ccxseg");
    let dst = paths.shard_dir.join(&rel);
    std::fs::copy(&fixture_seg, &dst)?;

    // Write MANIFEST referencing the fixture segment (Phase 2/3 layout).
    let mut mf = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&paths.manifest_path)?;
    let hdr = encode_manifest_header_v1(shard_id, epoch, /*created_at_unix_ns=*/ 123)?;
    mf.write_all(&hdr)?;

    let seg_meta = SegmentMeta {
        level: 0,
        shard_id,
        epoch,
        segment_seq: footer.segment_seq,
        segment_id: footer.segment_id,
        relative_path: rel,
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
    let rec = encode_manifest_add_segment_v1(&seg_meta)?;
    let framed = frame_manifest_record(&rec);
    mf.write_all(&framed)?;
    mf.sync_all()?;

    let cuda_enabled = false;
    let cuda_driver_version: Option<String> = None;
    let device_name: Option<String> = None;

    let storage = ShardStorage::open(root, shard_id, epoch, ShardStorageOptions::default())?;

    let (frames, end) = storage.replay_from(None, 0)?;
    if end.is_some() {
        return Err("fixture replay unexpectedly returned a cursor (expected full replay)".into());
    }

    let (total_frames, digest_blake3) = replay_digest(&frames);
    Ok(FixtureDigestReport {
        fixture: fixture_seg.file_stem().map_or_else(
            || fixture_seg.display().to_string(),
            |v| v.to_string_lossy().to_string(),
        ),
        shard_id,
        epoch,
        segment_seq: footer.segment_seq,
        cuda_enabled,
        cuda_driver_version,
        device_index,
        device_name,
        total_frames,
        digest_blake3,
    })
}

pub fn segment_fixture_replay_digest(
    fixture: &str,
    device_index: i32,
) -> Result<FixtureDigestReport, Box<dyn std::error::Error + Send + Sync>> {
    let fixture_seg = fixture_segment_path(fixture)?;
    segment_replay_digest_from_segment_path(&fixture_seg, device_index)
}
