// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use super::{
    io_err, read_bytes, read_u16, read_u32, read_u64, DirRunKey, DirRunMeta, ManifestSegmentCatalogV1, Result,
    SegmentMeta, StorageError, StreamMeta, MANIFEST_HEADER_LEN, MANIFEST_MAGIC_CCMF, MANIFEST_VERSION_V1,
};
use corecrux_segment::SegmentId;
use std::collections::HashMap;
use std::fs::File;
use std::io::SeekFrom;
use std::io::{Read, Seek};
use std::path::Path;

const MANIFEST_RECORD_TYPE_ADD_SEGMENT_V1: u8 = 1;
const MANIFEST_RECORD_TYPE_ADD_DIR_RUN_V1: u8 = 10;
const MANIFEST_RECORD_TYPE_REMOVE_DIR_RUN_V1: u8 = 11;
const MANIFEST_RECORD_TYPE_STREAM_META_UPDATE_V1: u8 = 20;

#[derive(Debug, Clone, Copy)]
pub(crate) struct StreamMetaUpdateV1 {
    pub(crate) stream_hash: u64,
    pub(crate) min_live_seq: u64,
    pub(crate) tombstone_seq: u64,
    pub(crate) gen: u64,
}

#[derive(Debug, Clone)]
pub(crate) enum ManifestRecord {
    AddSegment(SegmentMeta),
    AddDirRun(DirRunMeta),
    RemoveDirRun(DirRunKey),
    StreamMetaUpdate(StreamMetaUpdateV1),
}

#[derive(Debug, Default)]
pub(crate) struct ManifestState {
    pub(crate) segments_by_seq: HashMap<u64, SegmentMeta>,
    pub(crate) dir_runs: HashMap<DirRunKey, DirRunMeta>,
    pub(crate) stream_meta: HashMap<u64, StreamMeta>,
}

impl ManifestState {
    fn apply(&mut self, rec: ManifestRecord) {
        match rec {
            ManifestRecord::AddSegment(seg) => {
                self.segments_by_seq.insert(seg.segment_seq, seg);
            }
            ManifestRecord::AddDirRun(run) => {
                self.dir_runs.insert(run.key, run);
            }
            ManifestRecord::RemoveDirRun(key) => {
                self.dir_runs.remove(&key);
            }
            ManifestRecord::StreamMetaUpdate(upd) => {
                let e = self.stream_meta.entry(upd.stream_hash).or_default();
                e.min_live_seq = e.min_live_seq.max(upd.min_live_seq);
                e.tombstone_seq = e.tombstone_seq.max(upd.tombstone_seq);
            }
        }
    }
}

pub fn encode_manifest_header_v1(
    shard_id: u32,
    epoch: u64,
    created_at_unix_ns: u64,
) -> Result<[u8; MANIFEST_HEADER_LEN]> {
    let mut out = [0u8; MANIFEST_HEADER_LEN];
    out[0..4].copy_from_slice(&MANIFEST_MAGIC_CCMF.to_le_bytes());
    out[4..6].copy_from_slice(&MANIFEST_VERSION_V1.to_le_bytes());
    out[8..12].copy_from_slice(&(MANIFEST_HEADER_LEN as u32).to_le_bytes());
    out[12..16].copy_from_slice(&shard_id.to_le_bytes());
    out[16..24].copy_from_slice(&epoch.to_le_bytes());
    out[24..32].copy_from_slice(&created_at_unix_ns.to_le_bytes());

    let crc = crc32c::crc32c(&out[..MANIFEST_HEADER_LEN - 4]);
    out[MANIFEST_HEADER_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
    Ok(out)
}

pub fn load_manifest_segment_catalog(shard_dir: &Path) -> Result<ManifestSegmentCatalogV1> {
    let manifest_path = shard_dir.join("MANIFEST");
    let mut manifest = File::open(&manifest_path).map_err(io_err)?;

    let mut header = [0u8; MANIFEST_HEADER_LEN];
    manifest.read_exact(&mut header).map_err(io_err)?;
    validate_manifest_header(&header)?;

    let mut shard_id_bytes = [0u8; 4];
    shard_id_bytes.copy_from_slice(&header[12..16]);
    let mut epoch_bytes = [0u8; 8];
    epoch_bytes.copy_from_slice(&header[16..24]);

    manifest.seek(SeekFrom::Start(0)).map_err(io_err)?;
    let (state, manifest_end) = load_manifest_records(&mut manifest)?;
    let mut segments: Vec<SegmentMeta> = state.segments_by_seq.into_values().collect();
    segments.sort_by_key(|segment| segment.segment_seq);

    Ok(ManifestSegmentCatalogV1 {
        shard_id: u32::from_le_bytes(shard_id_bytes),
        epoch: u64::from_le_bytes(epoch_bytes),
        manifest_end,
        segments,
    })
}

// SAFETY: try_into().unwrap() on fixed-size byte slices with matching array length.
#[allow(clippy::unwrap_used)]
pub(crate) fn load_manifest_records(manifest: &mut File) -> Result<(ManifestState, u64)> {
    manifest.seek(SeekFrom::Start(0)).map_err(io_err)?;
    let mut hdr = [0u8; MANIFEST_HEADER_LEN];
    manifest.read_exact(&mut hdr).map_err(io_err)?;
    validate_manifest_header(&hdr)?;

    let mut state = ManifestState::default();

    let mut offset = MANIFEST_HEADER_LEN as u64;
    loop {
        let mut len_buf = [0u8; 8];
        match manifest.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(io_err(e));
            }
        }
        let record_len = u32::from_le_bytes(len_buf[0..4].try_into().unwrap()) as usize;
        let expected_crc = u32::from_le_bytes(len_buf[4..8].try_into().unwrap());

        if record_len == 0 || record_len > 64 * 1024 * 1024 {
            break;
        }

        let mut rec = vec![0u8; record_len];
        if let Err(e) = manifest.read_exact(&mut rec) {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                break;
            }
            return Err(io_err(e));
        }
        let actual_crc = crc32c::crc32c(&rec);
        if actual_crc != expected_crc {
            // Tail is corrupt; stop and allow truncation.
            break;
        }

        if let Some(seg) = parse_manifest_record(&rec)? {
            state.apply(seg);
        }

        offset += 8 + (record_len as u64);
    }

    // If file has a junk tail, truncate to last good offset.
    let meta_len = manifest.metadata().map_err(io_err)?.len();
    if meta_len > offset {
        manifest.set_len(offset).map_err(io_err)?;
        manifest.sync_all().map_err(io_err)?;
    }

    Ok((state, offset))
}

// SAFETY: try_into().unwrap() on fixed-size byte slices with matching array length.
#[allow(clippy::unwrap_used)]
pub(crate) fn validate_manifest_header(bytes: &[u8]) -> Result<()> {
    if bytes.len() < MANIFEST_HEADER_LEN {
        return Err(StorageError::ManifestHeaderInvalid {
            msg: "too small".to_string(),
        });
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    if magic != MANIFEST_MAGIC_CCMF {
        return Err(StorageError::ManifestHeaderInvalid {
            msg: format!("bad magic: {magic:#x}"),
        });
    }
    let ver = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    if ver != MANIFEST_VERSION_V1 {
        return Err(StorageError::ManifestHeaderInvalid {
            msg: format!("bad version: {ver}"),
        });
    }
    let header_len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    if header_len != MANIFEST_HEADER_LEN {
        return Err(StorageError::ManifestHeaderInvalid {
            msg: format!("bad header_len: {header_len}"),
        });
    }
    let expected = u32::from_le_bytes(bytes[MANIFEST_HEADER_LEN - 4..].try_into().unwrap());
    let actual = crc32c::crc32c(&bytes[..MANIFEST_HEADER_LEN - 4]);
    if expected != actual {
        return Err(StorageError::ManifestCrcMismatch { expected, actual });
    }
    Ok(())
}

pub fn frame_manifest_record(record_bytes: &[u8]) -> Vec<u8> {
    let len = record_bytes.len() as u32;
    let crc = crc32c::crc32c(record_bytes);
    let mut out = Vec::with_capacity(8 + record_bytes.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(record_bytes);
    out
}

fn parse_manifest_record(bytes: &[u8]) -> Result<Option<ManifestRecord>> {
    if bytes.len() < 4 {
        return Err(StorageError::ManifestRecordInvalid {
            msg: "too small".to_string(),
        });
    }
    let record_type = bytes[0];
    let record_version = bytes[1];
    if record_version != 1 {
        return Ok(None);
    }
    match record_type {
        MANIFEST_RECORD_TYPE_ADD_SEGMENT_V1 => Ok(Some(ManifestRecord::AddSegment(parse_add_segment_v1(bytes)?))),
        MANIFEST_RECORD_TYPE_ADD_DIR_RUN_V1 => Ok(Some(ManifestRecord::AddDirRun(parse_add_dir_run_v1(bytes)?))),
        MANIFEST_RECORD_TYPE_REMOVE_DIR_RUN_V1 => {
            Ok(Some(ManifestRecord::RemoveDirRun(parse_remove_dir_run_v1(bytes)?)))
        }
        MANIFEST_RECORD_TYPE_STREAM_META_UPDATE_V1 => Ok(Some(ManifestRecord::StreamMetaUpdate(
            parse_stream_meta_update_v1(bytes)?,
        ))),
        _ => Ok(None),
    }
}

fn parse_add_segment_v1(bytes: &[u8]) -> Result<SegmentMeta> {
    let mut cur = 4usize;
    let level = read_u32(bytes, &mut cur)?;
    let shard_id = read_u32(bytes, &mut cur)?;
    let epoch = read_u64(bytes, &mut cur)?;
    let segment_seq = read_u64(bytes, &mut cur)?;
    let mut segment_id = [0u8; 16];
    segment_id.copy_from_slice(read_bytes(bytes, &mut cur, 16)?);
    let file_len = read_u64(bytes, &mut cur)?;
    let path_len = read_u16(bytes, &mut cur)? as usize;
    let path = read_bytes(bytes, &mut cur, path_len)?;
    let relative_path = std::str::from_utf8(path)
        .map_err(|e| StorageError::ManifestRecordInvalid { msg: e.to_string() })?
        .to_string();
    let created_at_unix_ns = read_u64(bytes, &mut cur)?;
    let sealed_at_unix_ns = read_u64(bytes, &mut cur)?;
    let toc_offset = read_u64(bytes, &mut cur)?;
    let toc_len = read_u64(bytes, &mut cur)?;
    let toc_entry_count = read_u64(bytes, &mut cur)?;
    let min_stream_hash = read_u64(bytes, &mut cur)?;
    let min_seq = read_u64(bytes, &mut cur)?;
    let max_stream_hash = read_u64(bytes, &mut cur)?;
    let max_seq = read_u64(bytes, &mut cur)?;
    let mut segment_hash = [0u8; 32];
    segment_hash.copy_from_slice(read_bytes(bytes, &mut cur, 32)?);

    Ok(SegmentMeta {
        level,
        shard_id,
        epoch,
        segment_seq,
        segment_id: SegmentId(segment_id),
        relative_path,
        file_len,
        created_at_unix_ns,
        sealed_at_unix_ns,
        toc_offset,
        toc_len,
        toc_entry_count,
        min_stream_hash,
        min_seq,
        max_stream_hash,
        max_seq,
        segment_hash,
    })
}

pub fn encode_manifest_add_segment_v1(seg: &SegmentMeta) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    out.push(MANIFEST_RECORD_TYPE_ADD_SEGMENT_V1); // record_type
    out.push(1u8); // record_version
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&seg.level.to_le_bytes());
    out.extend_from_slice(&seg.shard_id.to_le_bytes());
    out.extend_from_slice(&seg.epoch.to_le_bytes());
    out.extend_from_slice(&seg.segment_seq.to_le_bytes());
    out.extend_from_slice(&seg.segment_id.0);
    out.extend_from_slice(&seg.file_len.to_le_bytes());
    if seg.relative_path.len() > u16::MAX as usize {
        return Err(StorageError::ManifestRecordInvalid {
            msg: "path too long".to_string(),
        });
    }
    out.extend_from_slice(&(seg.relative_path.len() as u16).to_le_bytes());
    out.extend_from_slice(seg.relative_path.as_bytes());
    out.extend_from_slice(&seg.created_at_unix_ns.to_le_bytes());
    out.extend_from_slice(&seg.sealed_at_unix_ns.to_le_bytes());
    out.extend_from_slice(&seg.toc_offset.to_le_bytes());
    out.extend_from_slice(&seg.toc_len.to_le_bytes());
    out.extend_from_slice(&seg.toc_entry_count.to_le_bytes());
    out.extend_from_slice(&seg.min_stream_hash.to_le_bytes());
    out.extend_from_slice(&seg.min_seq.to_le_bytes());
    out.extend_from_slice(&seg.max_stream_hash.to_le_bytes());
    out.extend_from_slice(&seg.max_seq.to_le_bytes());
    out.extend_from_slice(&seg.segment_hash);
    Ok(out)
}

fn parse_add_dir_run_v1(bytes: &[u8]) -> Result<DirRunMeta> {
    let mut cur = 4usize;
    let level = read_u32(bytes, &mut cur)?;
    let _shard_id = read_u32(bytes, &mut cur)?;
    let _epoch = read_u64(bytes, &mut cur)?;
    let run_id = read_u64(bytes, &mut cur)?;
    let file_len = read_u64(bytes, &mut cur)?;
    let path_len = read_u16(bytes, &mut cur)? as usize;
    let path = read_bytes(bytes, &mut cur, path_len)?;
    let relative_path = std::str::from_utf8(path)
        .map_err(|e| StorageError::ManifestRecordInvalid { msg: e.to_string() })?
        .to_string();
    let created_at_unix_ns = read_u64(bytes, &mut cur)?;
    let record_count = read_u64(bytes, &mut cur)?;

    Ok(DirRunMeta {
        key: DirRunKey { level, run_id },
        relative_path,
        file_len,
        created_at_unix_ns,
        record_count,
    })
}

fn parse_remove_dir_run_v1(bytes: &[u8]) -> Result<DirRunKey> {
    let mut cur = 4usize;
    let level = read_u32(bytes, &mut cur)?;
    let run_id = read_u64(bytes, &mut cur)?;
    Ok(DirRunKey { level, run_id })
}

fn parse_stream_meta_update_v1(bytes: &[u8]) -> Result<StreamMetaUpdateV1> {
    let mut cur = 4usize;
    let stream_hash = read_u64(bytes, &mut cur)?;
    let min_live_seq = read_u64(bytes, &mut cur)?;
    let tombstone_seq = read_u64(bytes, &mut cur)?;
    let gen = read_u64(bytes, &mut cur)?;
    Ok(StreamMetaUpdateV1 {
        stream_hash,
        min_live_seq,
        tombstone_seq,
        gen,
    })
}

pub(crate) fn encode_manifest_add_dir_run_v1(shard_id: u32, epoch: u64, run: &DirRunMeta) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    out.push(MANIFEST_RECORD_TYPE_ADD_DIR_RUN_V1); // record_type
    out.push(1u8); // record_version
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&run.key.level.to_le_bytes());
    out.extend_from_slice(&shard_id.to_le_bytes());
    out.extend_from_slice(&epoch.to_le_bytes());
    out.extend_from_slice(&run.key.run_id.to_le_bytes());
    out.extend_from_slice(&run.file_len.to_le_bytes());
    if run.relative_path.len() > u16::MAX as usize {
        return Err(StorageError::ManifestRecordInvalid {
            msg: "dir run path too long".to_string(),
        });
    }
    out.extend_from_slice(&(run.relative_path.len() as u16).to_le_bytes());
    out.extend_from_slice(run.relative_path.as_bytes());
    out.extend_from_slice(&run.created_at_unix_ns.to_le_bytes());
    out.extend_from_slice(&run.record_count.to_le_bytes());
    Ok(out)
}

pub(crate) fn encode_manifest_remove_dir_run_v1(key: DirRunKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.push(MANIFEST_RECORD_TYPE_REMOVE_DIR_RUN_V1); // record_type
    out.push(1u8); // record_version
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&key.level.to_le_bytes());
    out.extend_from_slice(&key.run_id.to_le_bytes());
    out
}

pub(crate) fn encode_manifest_stream_meta_update_v1(upd: StreamMetaUpdateV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.push(MANIFEST_RECORD_TYPE_STREAM_META_UPDATE_V1); // record_type
    out.push(1u8); // record_version
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&upd.stream_hash.to_le_bytes());
    out.extend_from_slice(&upd.min_live_seq.to_le_bytes());
    out.extend_from_slice(&upd.tombstone_seq.to_le_bytes());
    out.extend_from_slice(&upd.gen.to_le_bytes());
    out
}
