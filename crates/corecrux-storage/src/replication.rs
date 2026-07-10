// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Replication apply path — accepts a serialised sealed segment + manifest, materialises it on the receiver.

use super::{
    build_trailer_stream_ranges, fsync_dir, hex16, io_err, normalize_hash16_prefix, write_new_file_host, DirExtentV1,
    DirRunKey, FrameLocation, IdemEntry, IdemKey, ReplicatedSegmentApplyResultV1, Result, SegmentMeta, ShardStorage,
    StorageError, StreamSegmentRef,
};
use corecrux_segment::{decode_segment_v1, decode_trailer_index_v1};
use std::fs::File;

impl ShardStorage {
    /// Phase 11: install a sealed segment received from a leader onto a follower shard.
    ///
    /// This preserves the same durability boundary as local append:
    /// write segment bytes -> rename into `segments/` -> append MANIFEST AddSegment record.
    pub fn apply_replicated_segment_v1(&mut self, segment_bytes: &[u8]) -> Result<ReplicatedSegmentApplyResultV1> {
        // Followers should not have local head writes, but sealing here keeps state transitions
        // deterministic if a host is repurposed.
        self.seal_head_segment_if_any()?;

        let (_hdr, toc_hdr, entries, footer) = decode_segment_v1(segment_bytes)?;

        if footer.shard_id != self.shard_id {
            return Err(StorageError::FailedPrecondition {
                code: "REPLICATION_SHARD_MISMATCH".to_string(),
                msg: format!(
                    "replicated segment shard_id={} does not match local shard_id={}",
                    footer.shard_id, self.shard_id
                ),
            });
        }
        if footer.epoch != self.epoch {
            return Err(StorageError::FailedPrecondition {
                code: "REPLICATION_EPOCH_MISMATCH".to_string(),
                msg: format!(
                    "replicated segment epoch={} does not match local epoch={}",
                    footer.epoch, self.epoch
                ),
            });
        }

        let segment_seq = footer.segment_seq;
        let segment_id = footer.segment_id;

        if let Some(existing) = self.segments_by_seq.get(&segment_seq) {
            if existing.segment_hash == footer.segment_hash
                && existing.file_len == footer.file_len
                && existing.segment_id == segment_id
            {
                return Ok(ReplicatedSegmentApplyResultV1 {
                    applied: false,
                    shard_id: self.shard_id,
                    epoch: self.epoch,
                    segment_seq,
                    segment_id,
                    segment_hash: footer.segment_hash,
                    file_len: footer.file_len,
                });
            }
            return Err(StorageError::FailedPrecondition {
                code: "REPLICATION_SEGMENT_CONFLICT".to_string(),
                msg: format!(
                    "segment_seq={} already committed with different identity/hash",
                    segment_seq
                ),
            });
        }

        let tmp_rel = format!("tmp/seg-{segment_seq:020}-{}.partial", hex16(&segment_id.0));
        let final_rel = format!("segments/seg-{segment_seq:020}-{}.ccxseg", hex16(&segment_id.0));
        let tmp_path = self.paths.shard_dir.join(&tmp_rel);
        let final_path = self.paths.shard_dir.join(&final_rel);

        if final_path.exists() {
            let existing = std::fs::read(&final_path).map_err(io_err)?;
            let (_eh, _etoc_h, _eentries, existing_footer) = decode_segment_v1(&existing)?;
            if existing_footer.segment_hash != footer.segment_hash
                || existing_footer.file_len != footer.file_len
                || existing_footer.segment_seq != segment_seq
                || existing_footer.segment_id != segment_id
            {
                return Err(StorageError::FailedPrecondition {
                    code: "REPLICATION_FILE_CONFLICT".to_string(),
                    msg: format!("existing segment file conflicts for segment_seq={segment_seq}"),
                });
            }
        } else {
            write_new_file_host(&tmp_path, segment_bytes)?;
            std::fs::rename(&tmp_path, &final_path).map_err(io_err)?;
            fsync_dir(&self.paths.segments_dir)?;
        }

        let seg_meta = SegmentMeta {
            level: 0,
            shard_id: self.shard_id,
            epoch: self.epoch,
            segment_seq,
            segment_id,
            relative_path: final_rel.clone(),
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

        // MANIFEST append is the durable visibility boundary.
        self.append_manifest_add_segment(&seg_meta)?;

        let toc_off = footer.toc_offset as usize;
        let toc_len = footer.toc_len as usize;
        if toc_off + toc_len > segment_bytes.len() {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "toc area out of bounds".to_string(),
            });
        }
        let toc_area = &segment_bytes[toc_off..toc_off + toc_len];
        if let Some(ti) = decode_trailer_index_v1(toc_area, &toc_hdr)? {
            let ranges = build_trailer_stream_ranges(&ti);
            self.segment_trailers_by_seq.insert(segment_seq, ti);
            self.segment_stream_ranges_by_seq.insert(segment_seq, ranges);
        }
        let seg_file = File::open(&final_path).map_err(io_err)?;
        self.segment_files_by_seq.insert(segment_seq, seg_file);

        let mut dir_extents: Vec<DirExtentV1> = Vec::new();
        let mut i = 0usize;
        while i < entries.len() {
            let sh = entries[i].stream_hash;
            let min_seq = entries[i].seq;
            let mut max_seq = min_seq;
            i += 1;
            while i < entries.len() && entries[i].stream_hash == sh {
                max_seq = entries[i].seq;
                i += 1;
            }
            self.directory_by_stream.entry(sh).or_default().push(StreamSegmentRef {
                segment_seq,
                min_seq,
                max_seq,
            });
            dir_extents.push(DirExtentV1 {
                stream_hash: sh,
                min_seq,
                max_seq,
                segment_seq,
            });
        }
        for refs in self.directory_by_stream.values_mut() {
            refs.sort_by_key(|r| r.segment_seq);
        }

        // Rebuild next_seq + idempotency hot entries from the replicated TOC.
        for e in &entries {
            let stream_hash = e.stream_hash;
            let seq = e.seq;
            self.next_seq_by_stream
                .entry(stream_hash)
                .and_modify(|v| *v = (*v).max(seq.saturating_add(1)))
                .or_insert(seq.saturating_add(1));

            let mut h16 = [0u8; 16];
            h16.copy_from_slice(&e.event_id_hash16);
            let key = IdemKey {
                stream_hash,
                event_id_hash16: normalize_hash16_prefix(h16, self.options.event_id_hash_prefix_len),
            };
            let loc = FrameLocation {
                shard_id: self.shard_id as u64,
                epoch: self.epoch,
                segment_seq,
                offset: e.file_offset as u64,
            };
            self.idem_prefix_seen.insert(key);
            self.idem_hot.insert(key, IdemEntry { seq, loc });
        }

        let key = DirRunKey {
            level: 0,
            run_id: segment_seq,
        };
        let live = self.filter_extents_live(&dir_extents);
        let _ = self.publish_dir_run_v1(key, footer.sealed_at_unix_ns, &live)?;

        self.segments_by_seq.insert(segment_seq, seg_meta.clone());
        self.segments_in_order.push(seg_meta);
        self.segments_in_order.sort_by_key(|s| s.segment_seq);
        self.next_segment_seq = self.next_segment_seq.max(segment_seq.saturating_add(1));
        self.rebuild_tail_locator_from_directory()?;

        Ok(ReplicatedSegmentApplyResultV1 {
            applied: true,
            shard_id: self.shard_id,
            epoch: self.epoch,
            segment_seq,
            segment_id,
            segment_hash: footer.segment_hash,
            file_len: footer.file_len,
        })
    }

    /// Read a committed sealed segment payload for replication shipping.
    ///
    /// Returns the exact on-disk bytes and the canonical segment hash recorded in MANIFEST.
    pub fn read_segment_bytes_for_replication(&self, segment_seq: u64) -> Result<(Vec<u8>, [u8; 32])> {
        let seg = self
            .segments_by_seq
            .get(&segment_seq)
            .ok_or_else(|| StorageError::ManifestRecordInvalid {
                msg: format!("segment_seq {segment_seq} not found"),
            })?;
        let seg_path = self.paths.shard_dir.join(&seg.relative_path);
        let bytes = std::fs::read(&seg_path).map_err(io_err)?;
        let (_hdr, _toc, _entries, footer) = decode_segment_v1(&bytes)?;
        if footer.segment_hash != seg.segment_hash {
            return Err(StorageError::ManifestRecordInvalid {
                msg: format!(
                    "segment hash mismatch for segment_seq {segment_seq}: manifest={:?} footer={:?}",
                    seg.segment_hash, footer.segment_hash
                ),
            });
        }
        Ok((bytes, seg.segment_hash))
    }
}
