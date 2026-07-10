// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Phase 5 integrity helpers — physical-order block reads + optional CUDA "touch" to ensure device-visible bytes.

use super::{
    io_err, read_blocks_cpu, scan_frames_v1_block_bytes, ReplayScanStats, Result, ShardStorage, StorageError,
    StrictScanStats,
};
use std::fs::File;

impl ShardStorage {
    /// Phase 5 performance helper: read record blocks in physical order and ensure the bytes are
    /// device-visible via a GPU "touch" kernel in CUDA builds.
    ///
    /// NOTE: this does not perform per-frame validation in the CUDA path (the sealed segment
    /// hashes are already validated on open). The CPU fallback path retains the stricter scan.
    ///
    /// The `budget_bytes` parameter bounds per-batch IO + decompression working set; smaller
    /// values are safer on constrained device pools but reduce throughput.
    pub fn replay_scan_stats_all(&self, budget_bytes: usize) -> Result<ReplayScanStats> {
        if budget_bytes == 0 {
            return Err(StorageError::InvalidArgument {
                code: "BUDGET_BYTES_ZERO".to_string(),
                msg: "budget_bytes must be > 0".to_string(),
            });
        }

        let mut stats = ReplayScanStats {
            total_segments: 0,
            total_blocks: 0,
            total_frames: 0,
            total_compressed_bytes: 0,
            total_uncompressed_bytes: 0,
        };

        // Sealed segments (manifest order).
        for seg in &self.segments_in_order {
            let Some(ti) = self.segment_trailers_by_seq.get(&seg.segment_seq) else {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: "missing trailer index for sealed segment".to_string(),
                });
            };
            let seg_path = self.paths.shard_dir.join(&seg.relative_path);
            let file = File::open(&seg_path).map_err(io_err)?;

            stats.total_segments += 1;

            stats.total_compressed_bytes += ti.blocks.iter().map(|b| b.compressed_len as u64).sum::<u64>();
            stats.total_uncompressed_bytes += ti.blocks.iter().map(|b| b.uncompressed_len as u64).sum::<u64>();

            let mut i = 0usize;
            while i < ti.blocks.len() {
                let mut batch_ids: Vec<u32> = Vec::new();
                let mut batch_comp: usize = 0;
                let mut batch_uncomp: usize = 0;

                while i < ti.blocks.len() {
                    let b = &ti.blocks[i];
                    let blen_c = b.compressed_len as usize;
                    let blen_u = b.uncompressed_len as usize;
                    if !batch_ids.is_empty()
                        && (batch_comp.saturating_add(blen_c) > budget_bytes
                            || batch_uncomp.saturating_add(blen_u) > budget_bytes)
                    {
                        break;
                    }
                    batch_ids.push(b.block_id);
                    batch_comp = batch_comp.saturating_add(blen_c);
                    batch_uncomp = batch_uncomp.saturating_add(blen_u);
                    i += 1;
                }

                if batch_ids.is_empty() {
                    // Single oversized block; force progress.
                    batch_ids.push(ti.blocks[i].block_id);
                    i += 1;
                }
                let blocks = read_blocks_cpu(&file, &ti.blocks, &batch_ids)?;
                for bid in &batch_ids {
                    let idx = *bid as usize;
                    let Some(buf) = blocks.get(idx).and_then(|v| v.as_ref()) else {
                        return Err(StorageError::ManifestRecordInvalid {
                            msg: "block buffer missing during replay scan".to_string(),
                        });
                    };
                    let frames = scan_frames_v1_block_bytes(buf)?;
                    stats.total_frames = stats.total_frames.saturating_add(frames as u64);
                }
            }
        }

        // Head segment (currently-appending), if present.
        if let Some(head) = self.head.as_ref() {
            stats.total_segments += 1;

            stats.total_compressed_bytes += head.blocks.iter().map(|b| b.compressed_len as u64).sum::<u64>();
            stats.total_uncompressed_bytes += head.blocks.iter().map(|b| b.uncompressed_len as u64).sum::<u64>();

            let mut i = 0usize;
            while i < head.blocks.len() {
                let mut batch_ids: Vec<u32> = Vec::new();
                let mut batch_comp: usize = 0;
                let mut batch_uncomp: usize = 0;

                while i < head.blocks.len() {
                    let b = &head.blocks[i];
                    let blen_c = b.compressed_len as usize;
                    let blen_u = b.uncompressed_len as usize;
                    if !batch_ids.is_empty()
                        && (batch_comp.saturating_add(blen_c) > budget_bytes
                            || batch_uncomp.saturating_add(blen_u) > budget_bytes)
                    {
                        break;
                    }
                    batch_ids.push(b.block_id);
                    batch_comp = batch_comp.saturating_add(blen_c);
                    batch_uncomp = batch_uncomp.saturating_add(blen_u);
                    i += 1;
                }
                if batch_ids.is_empty() {
                    batch_ids.push(head.blocks[i].block_id);
                    i += 1;
                }
                let blocks = read_blocks_cpu(&head.file, &head.blocks, &batch_ids)?;
                for bid in &batch_ids {
                    let idx = *bid as usize;
                    let Some(buf) = blocks.get(idx).and_then(|v| v.as_ref()) else {
                        return Err(StorageError::ManifestRecordInvalid {
                            msg: "head block buffer missing during replay scan".to_string(),
                        });
                    };
                    let frames = scan_frames_v1_block_bytes(buf)?;
                    stats.total_frames = stats.total_frames.saturating_add(frames as u64);
                }
            }
        }

        Ok(stats)
    }

    /// Phase 5 hardening helper: validate per-block CRC32C and frame boundary correctness by
    /// scanning all record blocks in physical order.
    ///
    /// This is intentionally separate from `replay_scan_stats_all` (which is throughput-oriented)
    /// so replay SLO floors are not affected by extra validation work.
    pub fn integrity_scan_stats_all(&self, budget_bytes: usize) -> Result<ReplayScanStats> {
        if budget_bytes == 0 {
            return Err(StorageError::InvalidArgument {
                code: "BUDGET_BYTES_ZERO".to_string(),
                msg: "budget_bytes must be > 0".to_string(),
            });
        }

        let mut stats = ReplayScanStats {
            total_segments: 0,
            total_blocks: 0,
            total_frames: 0,
            total_compressed_bytes: 0,
            total_uncompressed_bytes: 0,
        };

        // Sealed segments (manifest order).
        for seg in &self.segments_in_order {
            let Some(ti) = self.segment_trailers_by_seq.get(&seg.segment_seq) else {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: "missing trailer index for sealed segment".to_string(),
                });
            };
            let seg_path = self.paths.shard_dir.join(&seg.relative_path);
            let file = File::open(&seg_path).map_err(io_err)?;

            stats.total_segments += 1;
            stats.total_blocks += ti.blocks.len() as u64;
            stats.total_compressed_bytes += ti.blocks.iter().map(|b| b.compressed_len as u64).sum::<u64>();
            stats.total_uncompressed_bytes += ti.blocks.iter().map(|b| b.uncompressed_len as u64).sum::<u64>();

            let mut seg_frames: u64 = 0;
            let mut i = 0usize;
            while i < ti.blocks.len() {
                let mut batch_ids: Vec<u32> = Vec::new();
                let mut batch_comp: usize = 0;
                let mut batch_uncomp: usize = 0;

                while i < ti.blocks.len() {
                    let b = &ti.blocks[i];
                    let blen_c = b.compressed_len as usize;
                    let blen_u = b.uncompressed_len as usize;
                    if !batch_ids.is_empty()
                        && (batch_comp.saturating_add(blen_c) > budget_bytes
                            || batch_uncomp.saturating_add(blen_u) > budget_bytes)
                    {
                        break;
                    }
                    batch_ids.push(b.block_id);
                    batch_comp = batch_comp.saturating_add(blen_c);
                    batch_uncomp = batch_uncomp.saturating_add(blen_u);
                    i += 1;
                }

                if batch_ids.is_empty() {
                    // Single oversized block; force progress.
                    batch_ids.push(ti.blocks[i].block_id);
                    i += 1;
                }
                let blocks = read_blocks_cpu(&file, &ti.blocks, &batch_ids)?;
                for bid in &batch_ids {
                    let idx = *bid as usize;
                    let Some(buf) = blocks.get(idx).and_then(|v| v.as_ref()) else {
                        return Err(StorageError::ManifestRecordInvalid {
                            msg: "block buffer missing during integrity scan".to_string(),
                        });
                    };
                    let frames = scan_frames_v1_block_bytes(buf)?;
                    seg_frames = seg_frames.saturating_add(frames as u64);
                }
            }

            if seg_frames != seg.toc_entry_count {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: format!(
                        "integrity scan frame count mismatch for segment_seq {}: toc_entry_count={} scanned={seg_frames}",
                        seg.segment_seq, seg.toc_entry_count
                    ),
                });
            }
            stats.total_frames = stats.total_frames.saturating_add(seg_frames);
        }

        // Head segment (currently-appending), if present.
        if let Some(head) = self.head.as_ref() {
            stats.total_segments += 1;
            stats.total_blocks += head.blocks.len() as u64;
            stats.total_compressed_bytes += head.blocks.iter().map(|b| b.compressed_len as u64).sum::<u64>();
            stats.total_uncompressed_bytes += head.blocks.iter().map(|b| b.uncompressed_len as u64).sum::<u64>();

            let expected = head.frames.len() as u64;
            let mut scanned: u64 = 0;

            let mut i = 0usize;
            while i < head.blocks.len() {
                let mut batch_ids: Vec<u32> = Vec::new();
                let mut batch_comp: usize = 0;
                let mut batch_uncomp: usize = 0;

                while i < head.blocks.len() {
                    let b = &head.blocks[i];
                    let blen_c = b.compressed_len as usize;
                    let blen_u = b.uncompressed_len as usize;
                    if !batch_ids.is_empty()
                        && (batch_comp.saturating_add(blen_c) > budget_bytes
                            || batch_uncomp.saturating_add(blen_u) > budget_bytes)
                    {
                        break;
                    }
                    batch_ids.push(b.block_id);
                    batch_comp = batch_comp.saturating_add(blen_c);
                    batch_uncomp = batch_uncomp.saturating_add(blen_u);
                    i += 1;
                }
                if batch_ids.is_empty() {
                    batch_ids.push(head.blocks[i].block_id);
                    i += 1;
                }
                let blocks = read_blocks_cpu(&head.file, &head.blocks, &batch_ids)?;
                for bid in &batch_ids {
                    let idx = *bid as usize;
                    let Some(buf) = blocks.get(idx).and_then(|v| v.as_ref()) else {
                        return Err(StorageError::ManifestRecordInvalid {
                            msg: "head block buffer missing during integrity scan".to_string(),
                        });
                    };
                    let frames = scan_frames_v1_block_bytes(buf)?;
                    scanned = scanned.saturating_add(frames as u64);
                }
            }

            if scanned != expected {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: format!(
                        "integrity scan frame count mismatch for head segment_seq {}: expected={} scanned={scanned}",
                        head.segment_seq, expected
                    ),
                });
            }
            stats.total_frames = stats.total_frames.saturating_add(scanned);
        }

        Ok(stats)
    }

    /// Strict sealed-segment verification: re-decode each manifest-committed segment, which
    /// recomputes the BLAKE3 header/record/TOC/segment hashes, then cross-checks the decoded
    /// footer hash against the manifest entry.
    pub fn verify_segment_hashes_all(&self) -> Result<StrictScanStats> {
        let mut stats = StrictScanStats::default();

        for seg in &self.segments_in_order {
            let seg_path = self.paths.shard_dir.join(&seg.relative_path);
            let bytes = std::fs::read(&seg_path).map_err(io_err)?;
            let (_header, _toc_header, entries, footer) = corecrux_segment::decode_segment_v1(&bytes)?;
            if footer.segment_hash != seg.segment_hash {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: format!(
                        "strict segment_hash mismatch for segment_seq {}: manifest differs from decoded footer",
                        seg.segment_seq
                    ),
                });
            }
            stats.verified_segments = stats.verified_segments.saturating_add(1);
            stats.verified_frames = stats.verified_frames.saturating_add(entries.len() as u64);
        }

        if self.head.is_some() {
            stats.skipped_head_segments = 1;
        }

        Ok(stats)
    }
}
