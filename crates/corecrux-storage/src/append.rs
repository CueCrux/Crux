// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Append-lane implementation — writes events to head blocks, builds tail locators, fences durability via fsync.

use super::companions::build_ccxi_companion;
use super::manifest::{
    encode_manifest_add_dir_run_v1, encode_manifest_add_segment_v1, encode_manifest_remove_dir_run_v1,
    encode_manifest_stream_meta_update_v1, frame_manifest_record, StreamMetaUpdateV1,
};
use super::{
    append_head_record_to_blocks, blake3_hash16, build_head_stream_tail_index, build_trailer_stream_ranges,
    compute_write_confirmation_receipt_hash, decode_commit_frame_v1, decode_dir_run_v1, deterministic_segment_id,
    dir_run_relative_path_v1, encode_commit_frame_v1, encode_dir_run_v1, failpoint_active,
    find_last_valid_commit_frame, fsync_dir, hex16, io_err, normalize_hash16_prefix, now_unix_ns,
    parse_head_record_len, parse_segment_seq_from_filename, push_head_stream_tail_index, rejected_outcome,
    select_stream_tail_from_trailer_sorted, write_at_file, write_new_file_host, AppendEventInput, AppendOutcome,
    AppendStatsV1, AppendStatus, ColdBatchLookup, ColdBatchMatch, DirExtentV1, DirRunKey, DirRunMeta, FrameLocation,
    HeadFrameMeta, HeadSegment, IdemEntry, IdemKey, NewFrameMeta, Result, SealResultV1, SegmentMeta,
    SegmentSealMaterialV1, ShardStorage, StorageError, StreamSegmentRef, WriteConfirmationMaterialV1,
    COMMIT_FRAME_LEN_V1, COMMIT_FRAME_MAGIC_CCMT, STREAM_TAIL_LOCATOR_MAX_EVENTS,
};
use corecrux_frame::{
    canonical_header_bytes_v1, compute_header_hash, compute_payload_hash, decode_canonical_header_bytes_v1,
    CanonicalHeaderV1,
};
use corecrux_segment::{
    decode_frame_v1, decode_segment_v1, decode_trailer_index_v1, encode_frame_v1, BlockMetaV1, FrameInput,
    TocByOffsetEntryV1,
};
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;

impl ShardStorage {
    // SAFETY: try_into().unwrap() on fixed-size byte slices with matching array length.
    #[allow(clippy::unwrap_used)]
    pub(crate) fn load_head_segment_from_disk(&mut self) -> Result<()> {
        let mut candidates: Vec<(u64, PathBuf, String)> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&self.paths.segments_dir) {
            for e in rd.flatten() {
                let p = e.path();
                if !p.is_file() {
                    continue;
                }
                let name = match p.file_name().and_then(|s| s.to_str()) {
                    Some(s) => s.to_string(),
                    None => continue,
                };
                if !name.ends_with(".ccxhead") {
                    continue;
                }
                let Some(seq) = parse_segment_seq_from_filename(&name) else {
                    continue;
                };
                candidates.push((seq, p, name));
            }
        }
        if candidates.is_empty() {
            return Ok(());
        }

        // Keep the newest head by segment_seq; quarantine the rest.
        candidates.sort_by_key(|(seq, _, _)| *seq);
        // SAFETY: candidates is guaranteed non-empty — we returned early above if empty.
        #[allow(clippy::expect_used)]
        let (keep_seq, keep_path, keep_name) = candidates.pop().expect("candidates non-empty after is_empty check");
        for (_seq, path, name) in candidates {
            let dst = self
                .paths
                .quarantine_dir
                .join(format!("head-orphan-{}-{name}", now_unix_ns()));
            std::fs::rename(&path, &dst).map_err(io_err)?;
        }
        fsync_dir(&self.paths.segments_dir)?;
        fsync_dir(&self.paths.quarantine_dir)?;

        let bytes = std::fs::read(&keep_path).map_err(io_err)?;
        if bytes.len() < corecrux_segment::SEGMENT_HEADER_LEN {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "head segment file too small".to_string(),
            });
        }
        let seg_header = corecrux_segment::decode_segment_header_v1(&bytes[..corecrux_segment::SEGMENT_HEADER_LEN])?;
        if seg_header.shard_id != self.shard_id || seg_header.epoch != self.epoch {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "head segment header shard_id/epoch mismatch".to_string(),
            });
        }
        if seg_header.segment_seq != keep_seq {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "head segment filename seq does not match header".to_string(),
            });
        }

        // Phase 4 recovery: only bytes up to the last valid commit-frame boundary are durable.
        let recovered_commit = find_last_valid_commit_frame(&bytes);
        if let Some(cf) = recovered_commit {
            self.next_head_commit_id = self.next_head_commit_id.max(cf.commit_id.saturating_add(1));
        }

        let committed_end =
            recovered_commit.map_or(corecrux_segment::SEGMENT_HEADER_LEN, |cf| cf.commit_offset as usize);
        let mut truncate_to = committed_end;

        let mut cur = corecrux_segment::SEGMENT_HEADER_LEN;
        let mut record_len: u64 = 0;
        let mut blocks: Vec<BlockMetaV1> = Vec::new();
        let mut frames: Vec<HeadFrameMeta> = Vec::new();
        let mut stream_min_max: HashMap<u64, (u64, u64)> = HashMap::new();
        let mut commit_frame_count: u64 = 0;
        let mut last_commit_id: u64 = 0;

        while cur < committed_end {
            let Some(record_len_at_cur) = parse_head_record_len(&bytes, cur) else {
                truncate_to = cur;
                break;
            };
            let Some(end) = cur.checked_add(record_len_at_cur) else {
                truncate_to = cur;
                break;
            };
            if end > committed_end {
                truncate_to = cur;
                break;
            }

            let magic = u32::from_le_bytes(bytes[cur..cur + 4].try_into().unwrap());
            if magic == COMMIT_FRAME_MAGIC_CCMT {
                let commit_frame = decode_commit_frame_v1(&bytes[cur..end])?;
                if commit_frame.commit_offset != end as u64 {
                    truncate_to = cur;
                    break;
                }
                append_head_record_to_blocks(&mut blocks, record_len, &bytes[cur..end], None)?;
                record_len = record_len.saturating_add(record_len_at_cur as u64);
                commit_frame_count = commit_frame_count.saturating_add(1);
                last_commit_id = last_commit_id.max(commit_frame.commit_id);
                let _ = commit_frame.commit_seq;
                cur = end;
                continue;
            }

            let frame_bytes = &bytes[cur..end];
            let decoded = match decode_frame_v1(frame_bytes) {
                Ok(v) => v,
                Err(_) => {
                    truncate_to = cur;
                    break;
                }
            };
            if decoded.header_bytes.len() < 32 {
                truncate_to = cur;
                break;
            }
            let canonical_len = decoded.header_bytes.len() - 32;
            let canonical_bytes = &decoded.header_bytes[..canonical_len];
            let hdr = match decode_canonical_header_bytes_v1(canonical_bytes) {
                Ok(h) => h,
                Err(_) => {
                    truncate_to = cur;
                    break;
                }
            };
            let stream_hash = corecrux_frame::stream_hash_xxhash64(&hdr.tenant_id, &hdr.stream_type, &hdr.stream_id)
                .map_err(|e| StorageError::ManifestRecordInvalid {
                    msg: format!("invalid stream key in head segment: {e}"),
                })?;

            let record_off_u64 = record_len;
            let record_off_u32 = u32::try_from(record_off_u64).map_err(|_| StorageError::ManifestRecordInvalid {
                msg: "head segment record_off exceeds u32".to_string(),
            })?;
            let (block_id, in_block_offset) =
                append_head_record_to_blocks(&mut blocks, record_len, frame_bytes, Some(stream_hash))?;

            let event_id_hash = blake3_hash16(hdr.event_id.as_bytes());
            let mut header_digest8 = [0u8; 8];
            header_digest8.copy_from_slice(&decoded.header_bytes[canonical_len..canonical_len + 8]);
            let payload_hash = compute_payload_hash(&decoded.payload_bytes);
            let mut payload_digest8 = [0u8; 8];
            payload_digest8.copy_from_slice(&payload_hash[0..8]);

            frames.push(HeadFrameMeta {
                stream_hash,
                seq: hdr.seq,
                record_off: record_off_u32,
                frame_len: record_len_at_cur as u32,
                payload_len: decoded.payload_bytes.len() as u32,
                event_id_hash16: event_id_hash,
                header_digest8,
                payload_digest8,
                block_id,
                in_block_offset,
            });

            stream_min_max
                .entry(stream_hash)
                .and_modify(|v| {
                    v.0 = v.0.min(hdr.seq);
                    v.1 = v.1.max(hdr.seq);
                })
                .or_insert((hdr.seq, hdr.seq));

            self.next_seq_by_stream
                .entry(stream_hash)
                .and_modify(|v| *v = (*v).max(hdr.seq + 1))
                .or_insert(hdr.seq + 1);

            let key = IdemKey {
                stream_hash,
                event_id_hash16: normalize_hash16_prefix(event_id_hash, self.options.event_id_hash_prefix_len),
            };
            let loc = FrameLocation {
                shard_id: self.shard_id as u64,
                epoch: self.epoch,
                segment_seq: seg_header.segment_seq,
                offset: (corecrux_segment::SEGMENT_HEADER_LEN as u64).saturating_add(record_off_u64),
            };
            self.idem_prefix_seen.insert(key);
            self.idem_hot.insert(key, IdemEntry { seq: hdr.seq, loc });

            record_len = record_len.saturating_add(record_len_at_cur as u64);
            cur = end;
        }

        if last_commit_id > 0 {
            self.next_head_commit_id = self.next_head_commit_id.max(last_commit_id.saturating_add(1));
        }

        let expected_end = (corecrux_segment::SEGMENT_HEADER_LEN as u64).saturating_add(record_len);
        if truncate_to > expected_end as usize {
            truncate_to = expected_end as usize;
        }
        if truncate_to < bytes.len() {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&keep_path)
                .map_err(io_err)?;
            file.set_len(truncate_to as u64).map_err(io_err)?;
            file.sync_all().map_err(io_err)?;
        }

        if frames.is_empty() {
            // No committed frames; remove the empty head segment.
            std::fs::remove_file(&keep_path).map_err(io_err)?;
            fsync_dir(&self.paths.segments_dir)?;
            return Ok(());
        }

        let stream_tail_idx_by_stream = build_head_stream_tail_index(&frames);
        let committed_region_crc32c =
            crc32c::crc32c(&bytes[corecrux_segment::SEGMENT_HEADER_LEN..(expected_end as usize)]);

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&keep_path)
            .map_err(io_err)?;
        self.head = Some(HeadSegment {
            segment_seq: seg_header.segment_seq,
            segment_id: seg_header.segment_id,
            created_at_unix_ns: seg_header.created_at_unix_ns,
            relative_path: format!("segments/{keep_name}"),
            file,
            record_len,
            frames,
            blocks,
            stream_min_max,
            stream_tail_idx_by_stream,
            committed_region_crc32c,
            commit_frame_count,
            last_commit_id,
        });
        Ok(())
    }

    pub(crate) fn seal_head_segment_if_any(&mut self) -> Result<()> {
        if self.head.is_some() {
            let _ = self.seal_head_segment()?;
        }
        Ok(())
    }

    pub(crate) fn seal_head_segment(&mut self) -> Result<SealResultV1> {
        let _seal_start = std::time::Instant::now();

        let Some(head) = self.head.take() else {
            return Ok(SealResultV1 {
                sealed: false,
                segment_seq: None,
                frame_count: None,
                seal_duration_secs: 0.0,
                seal_receipt: None,
            });
        };

        let seal_frame_count = head.frames.len() as u64;

        let head_path = self.paths.shard_dir.join(&head.relative_path);
        let bytes = std::fs::read(&head_path).map_err(io_err)?;
        if bytes.len() < corecrux_segment::SEGMENT_HEADER_LEN {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "head segment file too small".to_string(),
            });
        }
        let sealed_at = now_unix_ns();
        let mut record_area: Vec<u8> = Vec::with_capacity(head.record_len as usize);
        let mut metas: Vec<corecrux_segment::FrameMetaV1> = Vec::with_capacity(head.frames.len());
        for f in &head.frames {
            let src_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64).saturating_add(f.record_off as u64) as usize;
            let src_end = src_off.saturating_add(f.frame_len as usize);
            if src_end > bytes.len() {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: "head frame points outside segment bytes during seal".to_string(),
                });
            }
            let dst_off_u32 = u32::try_from(record_area.len()).map_err(|_| StorageError::ManifestRecordInvalid {
                msg: "sealed record_off exceeds u32".to_string(),
            })?;
            record_area.extend_from_slice(&bytes[src_off..src_end]);

            metas.push(corecrux_segment::FrameMetaV1 {
                stream_hash: f.stream_hash,
                seq: f.seq,
                record_off: dst_off_u32,
                frame_len: f.frame_len,
                payload_len: f.payload_len,
                event_id_hash16: f.event_id_hash16,
                header_digest8: f.header_digest8,
                payload_digest8: f.payload_digest8,
            });
        }

        let seg = corecrux_segment::seal_segment_v1_from_record_area_with_block_codec(
            self.shard_id,
            self.epoch,
            head.segment_seq,
            head.segment_id,
            head.created_at_unix_ns,
            sealed_at,
            self.options.record_block_codec,
            &record_area,
            &metas,
        )?;

        let segment_seq = head.segment_seq;
        let segment_id = head.segment_id;

        let tmp_rel = format!("tmp/seg-{segment_seq:020}-{}.partial", hex16(&segment_id.0));
        let final_rel = format!("segments/seg-{segment_seq:020}-{}.ccxseg", hex16(&segment_id.0));
        let tmp_path = self.paths.shard_dir.join(&tmp_rel);
        let final_path = self.paths.shard_dir.join(&final_rel);

        write_new_file_host(&tmp_path, &seg.bytes)?;

        if failpoint_active("after_write_tmp") {
            return Err(StorageError::Internal {
                msg: "failpoint: after_write_tmp".to_string(),
            });
        }

        std::fs::rename(&tmp_path, &final_path).map_err(io_err)?;
        fsync_dir(&self.paths.segments_dir)?;

        // CoreCrux v5: build .ccxi companion inverted index from sealed segment content.
        if self.options.build_ccxi {
            if let Err(err) = build_ccxi_companion(
                &self.paths.shard_dir,
                self.shard_id,
                self.epoch,
                segment_seq,
                &segment_id,
                &record_area,
                &metas,
            ) {
                tracing::warn!(?err, segment_seq, "ccxi-companion-build-failed");
                // Non-fatal: segment is sealed, just no companion index for this one.
            }
        }

        if failpoint_active("after_rename_before_manifest") {
            return Err(StorageError::Internal {
                msg: "failpoint: after_rename_before_manifest".to_string(),
            });
        }

        let seg_meta = SegmentMeta {
            level: 0,
            shard_id: self.shard_id,
            epoch: self.epoch,
            segment_seq,
            segment_id,
            relative_path: final_rel.clone(),
            file_len: seg.footer.file_len,
            created_at_unix_ns: head.created_at_unix_ns,
            sealed_at_unix_ns: sealed_at,
            toc_offset: seg.footer.toc_offset,
            toc_len: seg.footer.toc_len,
            toc_entry_count: seg.footer.toc_entry_count,
            min_stream_hash: seg.footer.min_stream_hash,
            min_seq: seg.footer.min_seq,
            max_stream_hash: seg.footer.max_stream_hash,
            max_seq: seg.footer.max_seq,
            segment_hash: seg.footer.segment_hash,
        };
        let seal_receipt = self.segment_seal_material_v1(&seg_meta, seal_frame_count);

        self.append_manifest_add_segment(&seg_meta)?;

        if failpoint_active("after_manifest_commit") {
            return Err(StorageError::Internal {
                msg: "failpoint: after_manifest_commit".to_string(),
            });
        }

        // Cache trailer index and update derived shard directory.
        let toc_off = seg.footer.toc_offset as usize;
        let toc_len = seg.footer.toc_len as usize;
        if toc_off + toc_len > seg.bytes.len() {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "toc area out of bounds".to_string(),
            });
        }
        let toc_area = &seg.bytes[toc_off..toc_off + toc_len];
        if let Some(ti) = decode_trailer_index_v1(toc_area, &seg.toc_header)? {
            let ranges = build_trailer_stream_ranges(&ti);
            self.segment_trailers_by_seq.insert(segment_seq, ti);
            self.segment_stream_ranges_by_seq.insert(segment_seq, ranges);
        }
        let seg_file = File::open(&final_path).map_err(io_err)?;
        self.segment_files_by_seq.insert(segment_seq, seg_file);

        let entries = &seg.toc_entries;
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

        // Phase 6: publish an L0 directory run for this sealed segment (derived from TOC).
        let live = self.filter_extents_live(&dir_extents);
        let key = DirRunKey {
            level: 0,
            run_id: segment_seq,
        };
        let _ = self.publish_dir_run_v1(key, sealed_at, &live)?;

        self.segments_by_seq.insert(segment_seq, seg_meta.clone());
        self.segments_in_order.push(seg_meta);
        self.segments_in_order.sort_by_key(|s| s.segment_seq);
        self.rebuild_tail_locator_from_directory()?;

        // Remove the head file now that the sealed segment is committed.
        std::fs::remove_file(&head_path).map_err(io_err)?;
        fsync_dir(&self.paths.segments_dir)?;

        let seal_elapsed = _seal_start.elapsed();
        tracing::info!(
            segment_seq,
            frame_count = seal_frame_count,
            seal_duration_ms = seal_elapsed.as_millis() as u64,
            "seal-head-segment-complete"
        );

        Ok(SealResultV1 {
            sealed: true,
            segment_seq: Some(segment_seq),
            frame_count: Some(seal_frame_count),
            seal_duration_secs: seal_elapsed.as_secs_f64(),
            seal_receipt: Some(seal_receipt),
        })
    }

    /// Force-seal the active head segment using the normal seal code path.
    ///
    /// Returns `SealResultV1 { sealed: false, .. }` if there is no active head.
    /// All invariants (TOC, BLAKE3, fsync, manifest append) are enforced.
    pub fn force_seal_head(&mut self) -> Result<SealResultV1> {
        self.seal_head_segment()
    }

    pub(crate) fn ensure_head_open(&mut self) -> Result<()> {
        if self.head.is_some() {
            return Ok(());
        }

        let segment_seq = self.next_segment_seq;
        self.next_segment_seq += 1;
        let segment_id = deterministic_segment_id(self.epoch, segment_seq);
        let created_at = now_unix_ns();

        let rel = format!("segments/seg-{segment_seq:020}-{}.ccxhead", hex16(&segment_id.0));
        let path = self.paths.shard_dir.join(&rel);

        let mut file = OpenOptions::new()
            .create_new(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(io_err)?;

        let header = corecrux_segment::SegmentHeaderV1 {
            flags: 1, // little_endian
            shard_id: self.shard_id,
            epoch: self.epoch,
            segment_seq,
            segment_id,
            created_at_unix_ns: created_at,
        };
        let header_bytes = corecrux_segment::encode_segment_header_v1(&header)?;

        // Establish durability for the header.
        file.write_all(&header_bytes).map_err(io_err)?;
        file.sync_all().map_err(io_err)?;
        fsync_dir(&self.paths.segments_dir)?;

        // Re-open the file handle without O_TRUNC semantics (paranoia).
        drop(file);
        file = OpenOptions::new().read(true).write(true).open(&path).map_err(io_err)?;

        self.head = Some(HeadSegment {
            segment_seq,
            segment_id,
            created_at_unix_ns: created_at,
            relative_path: rel,
            file,
            record_len: 0,
            frames: Vec::new(),
            blocks: Vec::new(),
            stream_min_max: HashMap::new(),
            stream_tail_idx_by_stream: HashMap::new(),
            committed_region_crc32c: 0,
            commit_frame_count: 0,
            last_commit_id: 0,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(
        level = "info",
        skip(self, events),
        fields(
            stream_hash,
            expected_next_seq,
            tenant_id = %tenant_id,
            stream_type = %stream_type,
            stream_id = %stream_id,
            events_len = events.len()
        )
    )]
    pub fn append_batch(
        &mut self,
        stream_hash: u64,
        expected_next_seq: u64,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        ingested_at_rfc3339: &str,
        events: &[AppendEventInput<'_>],
    ) -> Result<Vec<AppendOutcome>> {
        Ok(self
            .append_batch_with_stats(
                stream_hash,
                expected_next_seq,
                tenant_id,
                stream_type,
                stream_id,
                ingested_at_rfc3339,
                events,
            )?
            .0)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_batch_with_stats(
        &mut self,
        stream_hash: u64,
        expected_next_seq: u64,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        ingested_at_rfc3339: &str,
        events: &[AppendEventInput<'_>],
    ) -> Result<(Vec<AppendOutcome>, AppendStatsV1)> {
        let total_start = std::time::Instant::now();
        let mut stats = AppendStatsV1::default();

        // Host-level admission checks: explicit and bounded.
        if events.len() > self.options.max_events_per_batch {
            return Err(StorageError::ResourceExhausted {
                code: "BACKPRESSURE_MAX_EVENTS".to_string(),
                msg: format!(
                    "events.len={} exceeds max_events_per_batch={}",
                    events.len(),
                    self.options.max_events_per_batch
                ),
                retry_after_ms: Some(50),
            });
        }
        let mut batch_bytes: usize = 0;
        for ev in events {
            batch_bytes = batch_bytes.saturating_add(ev.payload_bytes.len());
            // event_id bytes are bounded independently; don't let a single oversize id turn into a
            // request-level backpressure when we can reject it per-event.
            batch_bytes = batch_bytes.saturating_add(ev.event_id.len().min(self.options.max_event_id_bytes));
        }
        if batch_bytes > self.options.max_batch_bytes {
            return Err(StorageError::ResourceExhausted {
                code: "BACKPRESSURE_MAX_BATCH_BYTES".to_string(),
                msg: format!(
                    "batch_bytes={} exceeds max_batch_bytes={}",
                    batch_bytes, self.options.max_batch_bytes
                ),
                retry_after_ms: Some(50),
            });
        }

        let current_next = *self.next_seq_by_stream.get(&stream_hash).unwrap_or(&1);
        if expected_next_seq != 0 && expected_next_seq != current_next {
            return Err(StorageError::ManifestRecordInvalid {
                msg: format!("expected_next_seq={expected_next_seq} does not match current_next_seq={current_next}"),
            });
        }

        if let Some(m) = self.stream_meta.get(&stream_hash) {
            if m.tombstone_seq > 0 {
                return Err(StorageError::FailedPrecondition {
                    code: "STREAM_TOMBSTONED".to_string(),
                    msg: format!("stream is tombstoned (tombstone_seq={})", m.tombstone_seq),
                });
            }
        }

        let mut header_bufs: Vec<Vec<u8>> = Vec::new();
        let mut new_frames: Vec<NewFrameMeta<'_>> = Vec::new();
        let mut outcomes: Vec<AppendOutcome> = Vec::with_capacity(events.len());
        let mut seq_cursor = current_next;
        let mut seen_in_batch: HashMap<&str, usize> = HashMap::new();
        let mut cold_lookup_cache: Option<ColdBatchLookup> = None;
        let cold_batch_prefixes: HashSet<[u8; 16]> = if self.idem_hot.is_incomplete() {
            events
                .iter()
                .filter_map(|ev| {
                    if ev.event_id.is_empty() || ev.event_id.len() > self.options.max_event_id_bytes {
                        return None;
                    }
                    Some(normalize_hash16_prefix(
                        blake3_hash16(ev.event_id.as_bytes()),
                        self.options.event_id_hash_prefix_len,
                    ))
                })
                .collect()
        } else {
            HashSet::new()
        };

        // Precompute outcomes and build frames for new events.
        for ev in events {
            let event_id = ev.event_id; // bytes-first: do not trim or normalize
            if event_id.is_empty() {
                outcomes.push(rejected_outcome("EVENT_ID_EMPTY", "event_id is empty".to_string()));
                continue;
            }
            if event_id.len() > self.options.max_event_id_bytes {
                outcomes.push(rejected_outcome(
                    "EVENT_ID_TOO_LARGE",
                    format!(
                        "event_id is {} bytes (max {})",
                        event_id.len(),
                        self.options.max_event_id_bytes
                    ),
                ));
                continue;
            }

            if let Some(&first_idx) = seen_in_batch.get(event_id) {
                let first = outcomes.get(first_idx).cloned().ok_or_else(|| StorageError::Internal {
                    msg: "intra-batch alias index out of bounds".to_string(),
                })?;
                if first.status == AppendStatus::Rejected {
                    outcomes.push(first);
                } else {
                    outcomes.push(AppendOutcome {
                        status: AppendStatus::DuplicateInBatch,
                        ..first
                    });
                }
                continue;
            }

            // First time we've seen this event_id in the request; stash the outcome index.
            seen_in_batch.insert(event_id, outcomes.len());

            let idempotency_start = std::time::Instant::now();
            let full_h16 = blake3_hash16(event_id.as_bytes());
            let key = IdemKey {
                stream_hash,
                event_id_hash16: normalize_hash16_prefix(full_h16, self.options.event_id_hash_prefix_len),
            };

            // Hot lookup (bounded) + verify-on-hit (bytes-first).
            if let Some(found) = self.lookup_duplicate_hot(&key, event_id)? {
                stats.add_idempotency_elapsed(idempotency_start.elapsed());
                outcomes.push(found);
                continue;
            }

            // Cold lookup is required when the hot cache is incomplete (evicted/truncated), but
            // only when this (stream_hash, event_id_hash_prefix) has been seen before.
            if self.idem_hot.is_incomplete() && self.idem_prefix_seen.contains(&key) {
                if cold_lookup_cache.is_none() {
                    cold_lookup_cache = Some(self.lookup_duplicate_cold_batch(stream_hash, &cold_batch_prefixes)?);
                }
                // SAFETY: cold_lookup_cache is set to Some on the line above this block.
                #[allow(clippy::expect_used)]
                let cold = cold_lookup_cache.as_ref().expect("cold lookup cache initialized");
                if let Some(found) = cold.find(key.event_id_hash16, event_id) {
                    // Warm the hot cache on cold hit.
                    self.idem_prefix_seen.insert(key);
                    self.idem_hot.insert(
                        key,
                        IdemEntry {
                            seq: found.seq,
                            loc: found.location.ok_or_else(|| StorageError::Internal {
                                msg: "cold duplicate missing location".to_string(),
                            })?,
                        },
                    );
                    stats.add_idempotency_elapsed(idempotency_start.elapsed());
                    outcomes.push(found);
                    continue;
                }
                if !cold.scanned_all {
                    return Err(StorageError::ResourceExhausted {
                        code: "BACKPRESSURE_COLD_IDEMPOTENCY".to_string(),
                        msg: format!(
                            "cold idempotency scan exceeded limit (scanned {} of {} segments)",
                            cold.scanned_segments, cold.total_segments
                        ),
                        retry_after_ms: Some(100),
                    });
                }
            }
            stats.add_idempotency_elapsed(idempotency_start.elapsed());

            let payload_hash = compute_payload_hash(ev.payload_bytes);
            let canonical = CanonicalHeaderV1 {
                tenant_id: tenant_id.to_string(),
                stream_id: stream_id.to_string(),
                stream_type: stream_type.to_string(),
                seq: seq_cursor,
                event_id: event_id.to_string(),
                occurred_at: ev.occurred_at.to_string(),
                ingested_at: ingested_at_rfc3339.to_string(),
                event_type: ev.event_type.to_string(),
                content_type: ev.content_type.to_string(),
                payload_len: ev.payload_bytes.len() as u32,
                payload_hash,
            };
            let canonical_bytes = canonical_header_bytes_v1(&canonical);
            let header_hash = compute_header_hash(&canonical_bytes);

            outcomes.push(AppendOutcome {
                status: AppendStatus::Appended,
                seq: seq_cursor,
                location: None, // patched after segment build
                payload_hash,
                header_hash,
                error_code: None,
                error_message: None,
            });

            let mut header_bytes_for_frame = Vec::with_capacity(canonical_bytes.len() + 32);
            header_bytes_for_frame.extend_from_slice(&canonical_bytes);
            header_bytes_for_frame.extend_from_slice(&header_hash);
            header_bufs.push(header_bytes_for_frame);
            new_frames.push(NewFrameMeta {
                event_id,
                payload_bytes: ev.payload_bytes,
                payload_hash,
                header_hash,
                seq: seq_cursor,
                header_buf_idx: header_bufs.len() - 1,
            });

            seq_cursor += 1;
        }

        if new_frames.is_empty() {
            stats.total_nanos = total_start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            return Ok((outcomes, stats));
        }

        if failpoint_active("after_seq_assignment") {
            return Err(StorageError::Internal {
                msg: "failpoint: after_seq_assignment".to_string(),
            });
        }

        let mut frames: Vec<FrameInput<'_>> = Vec::with_capacity(new_frames.len());
        for nf in &new_frames {
            frames.push(FrameInput {
                stream_hash,
                seq: nf.seq,
                event_id: nf.event_id,
                header_hash: nf.header_hash,
                payload_hash: nf.payload_hash,
                header_bytes: header_bufs[nf.header_buf_idx].as_slice(),
                payload_bytes: nf.payload_bytes,
            });
        }

        if self.options.head_max_record_bytes > 0 {
            // Phase 5: append into a currently-open head segment and only seal when the head
            // exceeds a bounded record-area threshold. This allows tail/range reads to include
            // not-yet-sealed bytes.

            #[derive(Debug)]
            struct EncodedNewFrame {
                seq: u64,
                frame_bytes: Vec<u8>,
                payload_len: u32,
                event_id_hash16: [u8; 16],
                header_digest8: [u8; 8],
                payload_digest8: [u8; 8],
            }

            let mut encoded: Vec<EncodedNewFrame> = Vec::with_capacity(new_frames.len());
            let mut encoded_frame_bytes: Vec<Vec<u8>> = Vec::with_capacity(new_frames.len());
            let mut total_bytes: usize = 0;
            for nf in &new_frames {
                let hb = header_bufs[nf.header_buf_idx].as_slice();
                let fb = encode_frame_v1(hb, nf.payload_bytes)?;
                total_bytes = total_bytes.saturating_add(fb.len());
                encoded_frame_bytes.push(fb.clone());

                let event_id_hash16 = blake3_hash16(nf.event_id.as_bytes());

                let mut header_digest8 = [0u8; 8];
                header_digest8.copy_from_slice(&nf.header_hash[0..8]);
                let mut payload_digest8 = [0u8; 8];
                payload_digest8.copy_from_slice(&nf.payload_hash[0..8]);

                encoded.push(EncodedNewFrame {
                    seq: nf.seq,
                    frame_bytes: fb,
                    payload_len: nf.payload_bytes.len() as u32,
                    event_id_hash16,
                    header_digest8,
                    payload_digest8,
                });
            }

            if encoded.is_empty() {
                stats.total_nanos = total_start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
                return Ok((outcomes, stats));
            }

            let batch_record_len = total_bytes.saturating_add(COMMIT_FRAME_LEN_V1);
            let max_head = self.options.head_max_record_bytes as u64;
            if let Some(h) = self.head.as_ref() {
                if h.record_len > 0 && h.record_len.saturating_add(batch_record_len as u64) > max_head {
                    // Keep head sizes bounded by sealing before a large append.
                    let _ = self.seal_head_segment()?;
                }
            }

            self.ensure_head_open()?;

            let (head_segment_seq, base_record_len, base_region_crc32c, commit_id) = {
                // SAFETY: ensure_head_open() is called above — head is guaranteed Some.
                #[allow(clippy::expect_used)]
                let head = self.head.as_ref().expect("head open");
                (
                    head.segment_seq,
                    head.record_len,
                    head.committed_region_crc32c,
                    self.next_head_commit_id,
                )
            };
            self.next_head_commit_id = self.next_head_commit_id.saturating_add(1);

            let commit_seq = encoded.last().map_or_else(|| seq_cursor.saturating_sub(1), |e| e.seq);
            let mut pre_commit_crc32c = base_region_crc32c;
            for e in &encoded {
                pre_commit_crc32c = crc32c::crc32c_append(pre_commit_crc32c, &e.frame_bytes);
            }
            let commit_offset = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                .saturating_add(base_record_len)
                .saturating_add(total_bytes as u64)
                .saturating_add(COMMIT_FRAME_LEN_V1 as u64);
            let commit_frame = encode_commit_frame_v1(commit_id, commit_seq, commit_offset, pre_commit_crc32c);
            let committed_region_crc32c = crc32c::crc32c_append(pre_commit_crc32c, &commit_frame);

            let write_offset = (corecrux_segment::SEGMENT_HEADER_LEN as u64).saturating_add(base_record_len);
            let mut append_bytes: Vec<u8> = Vec::with_capacity(batch_record_len);
            for e in &encoded {
                append_bytes.extend_from_slice(&e.frame_bytes);
            }
            append_bytes.extend_from_slice(&commit_frame);

            // Durably append event frames + commit frame, then fence before publishing outcomes.
            let io_write_start = std::time::Instant::now();
            {
                // SAFETY: ensure_head_open() called above — head is guaranteed Some.
                #[allow(clippy::expect_used)]
                let head_file = &self.head.as_ref().expect("head open").file;
                write_at_file(head_file, write_offset, &append_bytes)?;
                head_file.sync_all().map_err(io_err)?;
                stats.add_io_write_elapsed(io_write_start.elapsed());

                if failpoint_active("after_head_commit_frame_write_before_fence") {
                    return Err(StorageError::Internal {
                        msg: "failpoint: after_head_commit_frame_write_before_fence".to_string(),
                    });
                }

                if failpoint_active("after_head_commit_fence_before_ack") {
                    return Err(StorageError::Internal {
                        msg: "failpoint: after_head_commit_fence_before_ack".to_string(),
                    });
                }
            }

            // Publish locations + update derived head indexes + idempotency state.
            let index_update_start = std::time::Instant::now();
            let mut record_cursor = base_record_len;
            let mut new_head_entries_asc: Vec<TocByOffsetEntryV1> = Vec::with_capacity(encoded.len());
            {
                // SAFETY: ensure_head_open() called above — head is guaranteed Some.
                #[allow(clippy::expect_used)]
                let head = self.head.as_mut().expect("head open");

                for e in &encoded {
                    let frame_len_u32 =
                        u32::try_from(e.frame_bytes.len()).map_err(|_| StorageError::ManifestRecordInvalid {
                            msg: "frame too large".to_string(),
                        })?;
                    let record_off_u32 =
                        u32::try_from(record_cursor).map_err(|_| StorageError::ManifestRecordInvalid {
                            msg: "head record_off exceeds u32".to_string(),
                        })?;
                    let (block_id, in_block_offset) = append_head_record_to_blocks(
                        &mut head.blocks,
                        record_cursor,
                        &e.frame_bytes,
                        Some(stream_hash),
                    )?;

                    head.frames.push(HeadFrameMeta {
                        stream_hash,
                        seq: e.seq,
                        record_off: record_off_u32,
                        frame_len: frame_len_u32,
                        payload_len: e.payload_len,
                        event_id_hash16: e.event_id_hash16,
                        header_digest8: e.header_digest8,
                        payload_digest8: e.payload_digest8,
                        block_id,
                        in_block_offset,
                    });
                    let frame_idx = head.frames.len().saturating_sub(1);
                    push_head_stream_tail_index(&mut head.stream_tail_idx_by_stream, stream_hash, frame_idx, e.seq);
                    new_head_entries_asc.push(TocByOffsetEntryV1 {
                        stream_hash,
                        seq: e.seq,
                        block_id,
                        in_block_offset,
                        frame_len: frame_len_u32,
                        flags: 0,
                        event_id_hash16: e.event_id_hash16,
                        header_digest8: e.header_digest8,
                        payload_digest8: e.payload_digest8,
                    });

                    head.stream_min_max
                        .entry(stream_hash)
                        .and_modify(|v| {
                            v.0 = v.0.min(e.seq);
                            v.1 = v.1.max(e.seq);
                        })
                        .or_insert((e.seq, e.seq));

                    record_cursor = record_cursor.saturating_add(e.frame_bytes.len() as u64);
                }

                append_head_record_to_blocks(&mut head.blocks, record_cursor, &commit_frame, None)?;
                record_cursor = record_cursor.saturating_add(COMMIT_FRAME_LEN_V1 as u64);
                head.record_len = record_cursor;
                head.committed_region_crc32c = committed_region_crc32c;
                head.commit_frame_count = head.commit_frame_count.saturating_add(1);
                head.last_commit_id = commit_id;
            }

            // Patch outcomes + idempotency table now that locations are durable.
            record_cursor = base_record_len;
            for e in &encoded {
                let loc = FrameLocation {
                    shard_id: self.shard_id as u64,
                    epoch: self.epoch,
                    segment_seq: head_segment_seq,
                    offset: (corecrux_segment::SEGMENT_HEADER_LEN as u64).saturating_add(record_cursor),
                };

                let key = IdemKey {
                    stream_hash,
                    event_id_hash16: normalize_hash16_prefix(e.event_id_hash16, self.options.event_id_hash_prefix_len),
                };
                self.idem_prefix_seen.insert(key);
                self.idem_hot.insert(key, IdemEntry { seq: e.seq, loc });

                for o in outcomes.iter_mut().filter(|o| o.seq == e.seq && o.location.is_none()) {
                    o.location = Some(loc);
                }

                record_cursor = record_cursor.saturating_add(e.frame_bytes.len() as u64);
            }

            self.next_seq_by_stream.insert(stream_hash, seq_cursor);
            self.update_tail_locator_for_stream_entries(stream_hash, head_segment_seq, &new_head_entries_asc);
            stats.add_index_elapsed(index_update_start.elapsed());

            // Seal the head once it reaches the configured threshold.
            let should_seal = self.head.as_ref().is_some_and(|h| h.record_len >= max_head);
            if should_seal {
                let _ = self.seal_head_segment()?;
            }

            stats.write_confirmation = Some(WriteConfirmationMaterialV1 {
                commit_seq,
                segment_id: head_segment_seq,
                receipt_hash: compute_write_confirmation_receipt_hash(&encoded_frame_bytes),
            });
            stats.total_nanos = total_start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            return Ok((outcomes, stats));
        }

        // Phase 2: seal+commit one segment per AppendBatch (correctness first).
        let segment_seq = self.next_segment_seq;
        self.next_segment_seq += 1;
        let segment_id = deterministic_segment_id(self.epoch, segment_seq);
        let phase2_frame_bytes: Vec<Vec<u8>> = new_frames
            .iter()
            .map(|nf| {
                encode_frame_v1(header_bufs[nf.header_buf_idx].as_slice(), nf.payload_bytes)
                    .map_err(StorageError::Segment)
            })
            .collect::<Result<Vec<_>>>()?;

        let created_at = now_unix_ns();
        let sealed_at = created_at;

        let seg = corecrux_segment::build_segment_v1_with_block_codec(
            self.shard_id,
            self.epoch,
            segment_seq,
            segment_id,
            created_at,
            sealed_at,
            self.options.record_block_codec,
            &frames,
        )?;

        // Write to tmp file and fsync.
        let tmp_rel = format!("tmp/seg-{segment_seq:020}-{}.partial", hex16(&segment_id.0));
        let final_rel = format!("segments/seg-{segment_seq:020}-{}.ccxseg", hex16(&segment_id.0));
        let tmp_path = self.paths.shard_dir.join(&tmp_rel);
        let final_path = self.paths.shard_dir.join(&final_rel);

        {
            let io_write_start = std::time::Instant::now();
            write_new_file_host(&tmp_path, &seg.bytes)?;
            stats.add_io_write_elapsed(io_write_start.elapsed());
        }

        if failpoint_active("after_write_tmp") {
            return Err(StorageError::Internal {
                msg: "failpoint: after_write_tmp".to_string(),
            });
        }

        // Atomically move into segments/ before manifest publish.
        std::fs::rename(&tmp_path, &final_path).map_err(io_err)?;
        let fence_fsync_start = std::time::Instant::now();
        fsync_dir(&self.paths.segments_dir)?;
        stats.add_fence_fsync_elapsed(fence_fsync_start.elapsed());

        // CoreCrux v5: build .ccxi companion index (Phase 2 seal path).
        // Use the uncompressed frame bytes directly since the record area in seg.bytes
        // may be block-compressed (LZ4) and not directly parseable.
        if self.options.build_ccxi && !phase2_frame_bytes.is_empty() {
            // Concatenate frame bytes into a flat record area
            let mut flat_record: Vec<u8> = Vec::new();
            let mut phase2_metas: Vec<corecrux_segment::FrameMetaV1> = Vec::new();
            for (i, fb) in phase2_frame_bytes.iter().enumerate() {
                let record_off = flat_record.len() as u32;
                flat_record.extend_from_slice(fb);
                if let Some(toc_entry) = seg.toc_entries.get(i) {
                    phase2_metas.push(corecrux_segment::FrameMetaV1 {
                        stream_hash: toc_entry.stream_hash,
                        seq: toc_entry.seq,
                        record_off,
                        frame_len: fb.len() as u32,
                        payload_len: toc_entry.payload_len,
                        event_id_hash16: toc_entry.event_id_hash16,
                        header_digest8: toc_entry.header_digest8,
                        payload_digest8: toc_entry.payload_digest8,
                    });
                }
            }
            if let Err(err) = build_ccxi_companion(
                &self.paths.shard_dir,
                self.shard_id,
                self.epoch,
                segment_seq,
                &segment_id,
                &flat_record,
                &phase2_metas,
            ) {
                tracing::warn!(?err, segment_seq, "ccxi-companion-build-failed-phase2");
            }
        }

        if failpoint_active("after_rename_before_manifest") {
            return Err(StorageError::Internal {
                msg: "failpoint: after_rename_before_manifest".to_string(),
            });
        }

        // Append AddSegment record to MANIFEST as commit boundary.
        let seg_meta = SegmentMeta {
            level: 0,
            shard_id: self.shard_id,
            epoch: self.epoch,
            segment_seq,
            segment_id,
            relative_path: final_rel.clone(),
            file_len: seg.footer.file_len,
            created_at_unix_ns: created_at,
            sealed_at_unix_ns: sealed_at,
            toc_offset: seg.footer.toc_offset,
            toc_len: seg.footer.toc_len,
            toc_entry_count: seg.footer.toc_entry_count,
            min_stream_hash: seg.footer.min_stream_hash,
            min_seq: seg.footer.min_seq,
            max_stream_hash: seg.footer.max_stream_hash,
            max_seq: seg.footer.max_seq,
            segment_hash: seg.footer.segment_hash,
        };

        self.append_manifest_add_segment_with_stats(&seg_meta, Some(&mut stats))?;

        if failpoint_active("after_manifest_commit") {
            // Simulate crash after durable commit but before response/state publish.
            return Err(StorageError::Internal {
                msg: "failpoint: after_manifest_commit".to_string(),
            });
        }

        // Now we can publish locations and update in-memory state.
        let index_update_start = std::time::Instant::now();
        // We can recover file offsets by re-parsing the committed segment.
        let (_h, toc_h, entries, f) = decode_segment_v1(&seg.bytes)?;
        let toc_off = f.toc_offset as usize;
        let toc_len = f.toc_len as usize;
        if toc_off + toc_len > seg.bytes.len() {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "toc area out of bounds".to_string(),
            });
        }
        let toc_area = &seg.bytes[toc_off..toc_off + toc_len];
        let mut stream_tail_entries_asc: Vec<TocByOffsetEntryV1> = Vec::new();
        if let Some(ti) = decode_trailer_index_v1(toc_area, &toc_h)? {
            let mut tail = select_stream_tail_from_trailer_sorted(&ti, stream_hash, STREAM_TAIL_LOCATOR_MAX_EVENTS);
            tail.reverse();
            stream_tail_entries_asc = tail;
            let ranges = build_trailer_stream_ranges(&ti);
            self.segment_trailers_by_seq.insert(segment_seq, ti);
            self.segment_stream_ranges_by_seq.insert(segment_seq, ranges);
        }
        // Update shard directory for range/tail reads (derived index).
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

        // Phase 6: publish an L0 directory run for this sealed segment (derived from TOC).
        let live = self.filter_extents_live(&dir_extents);
        let key = DirRunKey {
            level: 0,
            run_id: segment_seq,
        };
        let _ = self.publish_dir_run_v1(key, sealed_at, &live)?;

        // Update idempotency hot cache and patch response locations by matching on (stream_hash, seq).
        let mut by_seq: HashMap<u64, &NewFrameMeta<'_>> = HashMap::new();
        for nf in &new_frames {
            by_seq.insert(nf.seq, nf);
        }
        for e in &entries {
            if e.stream_hash != stream_hash {
                continue;
            }
            let Some(nf) = by_seq.get(&e.seq) else {
                continue;
            };

            let loc = FrameLocation {
                shard_id: self.shard_id as u64,
                epoch: self.epoch,
                segment_seq,
                offset: e.file_offset as u64,
            };

            let full_h16 = blake3_hash16(nf.event_id.as_bytes());
            let key = IdemKey {
                stream_hash,
                event_id_hash16: normalize_hash16_prefix(full_h16, self.options.event_id_hash_prefix_len),
            };
            self.idem_prefix_seen.insert(key);
            self.idem_hot.insert(key, IdemEntry { seq: nf.seq, loc });

            // Patch the corresponding outcomes (Appended + any intra-batch aliases) by seq.
            for o in outcomes.iter_mut().filter(|o| o.seq == nf.seq && o.location.is_none()) {
                o.location = Some(loc);
            }
        }
        self.next_seq_by_stream.insert(stream_hash, seq_cursor);
        self.update_tail_locator_for_stream_entries(stream_hash, segment_seq, &stream_tail_entries_asc);

        self.segments_by_seq.insert(segment_seq, seg_meta.clone());
        let seg_file = File::open(&final_path).map_err(io_err)?;
        self.segment_files_by_seq.insert(segment_seq, seg_file);
        self.segments_in_order.push(seg_meta.clone());
        self.segments_in_order.sort_by_key(|s| s.segment_seq);
        stats.seal_receipt = Some(self.segment_seal_material_v1(&seg_meta, entries.len() as u64));
        stats.write_confirmation = Some(WriteConfirmationMaterialV1 {
            commit_seq: seg.footer.max_seq,
            segment_id: segment_seq,
            receipt_hash: compute_write_confirmation_receipt_hash(&phase2_frame_bytes),
        });
        stats.add_index_elapsed(index_update_start.elapsed());
        stats.total_nanos = total_start.elapsed().as_nanos().min(u64::MAX as u128) as u64;

        Ok((outcomes, stats))
    }

    fn segment_seal_material_v1(&self, seg: &SegmentMeta, frame_count: u64) -> SegmentSealMaterialV1 {
        let previous = self
            .segments_in_order
            .iter()
            .filter(|candidate| candidate.segment_seq < seg.segment_seq)
            .max_by_key(|candidate| candidate.segment_seq);
        SegmentSealMaterialV1 {
            shard_id: seg.shard_id,
            epoch: seg.epoch,
            segment_seq: seg.segment_seq,
            segment_id: seg.segment_id,
            segment_hash: seg.segment_hash,
            previous_segment_seq: previous.map(|candidate| candidate.segment_seq),
            previous_segment_hash: previous.map(|candidate| candidate.segment_hash),
            sealed_at_unix_ns: seg.sealed_at_unix_ns,
            frame_count,
        }
    }

    pub(crate) fn lookup_duplicate_hot(&self, key: &IdemKey, event_id: &str) -> Result<Option<AppendOutcome>> {
        let Some(candidates) = self.idem_hot.candidates(key) else {
            return Ok(None);
        };

        for e in candidates {
            let (hdr, payload_hash, header_hash) = self.read_canonical_and_hashes_for_location(e.loc)?;
            if hdr.event_id == event_id {
                return Ok(Some(AppendOutcome {
                    status: AppendStatus::DuplicateCommitted,
                    seq: e.seq,
                    location: Some(e.loc),
                    payload_hash,
                    header_hash,
                    error_code: None,
                    error_message: None,
                }));
            }
        }
        Ok(None)
    }

    pub(crate) fn lookup_duplicate_cold_batch(
        &self,
        stream_hash: u64,
        needed_prefixes: &HashSet<[u8; 16]>,
    ) -> Result<ColdBatchLookup> {
        if needed_prefixes.is_empty() {
            return Ok(ColdBatchLookup {
                scanned_all: true,
                ..ColdBatchLookup::default()
            });
        }

        let mut out = ColdBatchLookup::default();

        // Head segments are not tracked by MANIFEST. Include head bytes in the cold path so
        // idempotency remains correct when the hot cache is incomplete.
        if let Some(head) = self.head.as_ref() {
            if head.stream_min_max.contains_key(&stream_hash) {
                for f in head.frames.iter().rev() {
                    if f.stream_hash != stream_hash {
                        continue;
                    }
                    let norm = normalize_hash16_prefix(f.event_id_hash16, self.options.event_id_hash_prefix_len);
                    if !needed_prefixes.contains(&norm) {
                        continue;
                    }
                    let loc = FrameLocation {
                        shard_id: self.shard_id as u64,
                        epoch: self.epoch,
                        segment_seq: head.segment_seq,
                        offset: (corecrux_segment::SEGMENT_HEADER_LEN as u64).saturating_add(f.record_off as u64),
                    };
                    let (hdr, payload_hash, header_hash) = self.read_canonical_and_hashes_for_location(loc)?;
                    out.by_prefix.entry(norm).or_default().push(ColdBatchMatch {
                        event_id: hdr.event_id.clone(),
                        outcome: AppendOutcome {
                            status: AppendStatus::DuplicateCommitted,
                            seq: hdr.seq,
                            location: Some(loc),
                            payload_hash,
                            header_hash,
                            error_code: None,
                            error_message: None,
                        },
                    });
                }
            }
        }

        let total = self.segments_in_order.len();
        out.total_segments = total;
        if total == 0 {
            out.scanned_all = true;
            return Ok(out);
        }

        let cap = self.options.cold_scan_max_segments;
        if cap == 0 {
            return Err(StorageError::ResourceExhausted {
                code: "BACKPRESSURE_COLD_IDEMPOTENCY".to_string(),
                msg: "cold idempotency lookup disabled (cold_scan_max_segments=0)".to_string(),
                retry_after_ms: Some(100),
            });
        }

        let limit = total.min(cap);
        out.scanned_segments = limit;
        out.scanned_all = limit == total;

        for seg in self.segments_in_order.iter().rev().take(limit) {
            let seg_path = self.paths.shard_dir.join(&seg.relative_path);
            let bytes = std::fs::read(&seg_path).map_err(io_err)?;
            let (_h, _toc_h, entries, _f) = decode_segment_v1(&bytes)?;

            for e in entries {
                if e.stream_hash != stream_hash {
                    continue;
                }

                let mut h16 = [0u8; 16];
                h16.copy_from_slice(&e.event_id_hash16);
                let norm = normalize_hash16_prefix(h16, self.options.event_id_hash_prefix_len);
                if !needed_prefixes.contains(&norm) {
                    continue;
                }

                let off = e.file_offset as usize;
                let len = e.frame_len as usize;
                if off.saturating_add(len) > bytes.len() {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: "toc frame points outside file".to_string(),
                    });
                }

                let decoded = decode_frame_v1(&bytes[off..off + len])?;
                if decoded.header_bytes.len() < 32 {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: "stored frame header_bytes too small".to_string(),
                    });
                }
                let canonical_len = decoded.header_bytes.len() - 32;
                let canonical_bytes = &decoded.header_bytes[..canonical_len];
                let header = decode_canonical_header_bytes_v1(canonical_bytes).map_err(|err| {
                    StorageError::ManifestRecordInvalid {
                        msg: format!("failed to parse stored canonical header bytes: {err}"),
                    }
                })?;
                let header_hash = compute_header_hash(canonical_bytes);
                let payload_hash = compute_payload_hash(&decoded.payload_bytes);
                let loc = FrameLocation {
                    shard_id: self.shard_id as u64,
                    epoch: seg.epoch,
                    segment_seq: seg.segment_seq,
                    offset: e.file_offset as u64,
                };
                out.by_prefix.entry(norm).or_default().push(ColdBatchMatch {
                    event_id: header.event_id.clone(),
                    outcome: AppendOutcome {
                        status: AppendStatus::DuplicateCommitted,
                        seq: header.seq,
                        location: Some(loc),
                        payload_hash,
                        header_hash,
                        error_code: None,
                        error_message: None,
                    },
                });
            }
        }

        Ok(out)
    }

    #[allow(dead_code)]
    pub(crate) fn lookup_duplicate_cold(&self, key: &IdemKey, event_id: &str) -> Result<Option<AppendOutcome>> {
        // Head segments are not tracked by MANIFEST. If our hot cache is incomplete, we must
        // include head bytes in the cold path to preserve idempotency correctness.
        if let Some(head) = self.head.as_ref() {
            if head.stream_min_max.contains_key(&key.stream_hash) {
                for f in head.frames.iter().rev() {
                    if f.stream_hash != key.stream_hash {
                        continue;
                    }
                    let norm = normalize_hash16_prefix(f.event_id_hash16, self.options.event_id_hash_prefix_len);
                    if norm != key.event_id_hash16 {
                        continue;
                    }
                    let loc = FrameLocation {
                        shard_id: self.shard_id as u64,
                        epoch: self.epoch,
                        segment_seq: head.segment_seq,
                        offset: (corecrux_segment::SEGMENT_HEADER_LEN as u64).saturating_add(f.record_off as u64),
                    };
                    let (hdr, payload_hash, header_hash) = self.read_canonical_and_hashes_for_location(loc)?;
                    if hdr.event_id != event_id {
                        continue;
                    }
                    return Ok(Some(AppendOutcome {
                        status: AppendStatus::DuplicateCommitted,
                        seq: hdr.seq,
                        location: Some(loc),
                        payload_hash,
                        header_hash,
                        error_code: None,
                        error_message: None,
                    }));
                }
            }
        }

        let total = self.segments_in_order.len();
        if total == 0 {
            return Ok(None);
        }

        let cap = self.options.cold_scan_max_segments;
        if cap == 0 {
            return Err(StorageError::ResourceExhausted {
                code: "BACKPRESSURE_COLD_IDEMPOTENCY".to_string(),
                msg: "cold idempotency lookup disabled (cold_scan_max_segments=0)".to_string(),
                retry_after_ms: Some(100),
            });
        }

        let limit = total.min(cap);
        let scanned_all = limit == total;

        for seg in self.segments_in_order.iter().rev().take(limit) {
            let seg_path = self.paths.shard_dir.join(&seg.relative_path);
            let bytes = std::fs::read(&seg_path).map_err(io_err)?;
            let (_h, _toc_h, entries, _f) = decode_segment_v1(&bytes)?;

            for e in entries {
                if e.stream_hash != key.stream_hash {
                    continue;
                }

                let mut h16 = [0u8; 16];
                h16.copy_from_slice(&e.event_id_hash16);
                let norm = normalize_hash16_prefix(h16, self.options.event_id_hash_prefix_len);
                if norm != key.event_id_hash16 {
                    continue;
                }

                let frame = self.read_frame_bytes(seg.segment_seq, e.file_offset as u64)?;
                let decoded = decode_frame_v1(&frame)?;
                if decoded.header_bytes.len() < 32 {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: "stored frame header_bytes too small".to_string(),
                    });
                }

                let canonical_len = decoded.header_bytes.len() - 32;
                let canonical_bytes = &decoded.header_bytes[..canonical_len];
                let header = decode_canonical_header_bytes_v1(canonical_bytes).map_err(|err| {
                    StorageError::ManifestRecordInvalid {
                        msg: format!("failed to parse stored canonical header bytes: {err}"),
                    }
                })?;

                if header.event_id != event_id {
                    continue;
                }

                let header_hash = compute_header_hash(canonical_bytes);
                let payload_hash = compute_payload_hash(&decoded.payload_bytes);
                let loc = FrameLocation {
                    shard_id: self.shard_id as u64,
                    epoch: seg.epoch,
                    segment_seq: seg.segment_seq,
                    offset: e.file_offset as u64,
                };
                return Ok(Some(AppendOutcome {
                    status: AppendStatus::DuplicateCommitted,
                    seq: header.seq,
                    location: Some(loc),
                    payload_hash,
                    header_hash,
                    error_code: None,
                    error_message: None,
                }));
            }
        }

        if scanned_all {
            Ok(None)
        } else {
            Err(StorageError::ResourceExhausted {
                code: "BACKPRESSURE_COLD_IDEMPOTENCY".to_string(),
                msg: format!("cold idempotency scan exceeded limit (scanned {limit} of {total} segments)"),
                retry_after_ms: Some(100),
            })
        }
    }

    pub(crate) fn read_canonical_and_hashes_for_location(
        &self,
        loc: FrameLocation,
    ) -> Result<(CanonicalHeaderV1, [u8; 32], [u8; 32])> {
        let frame = self.read_frame_bytes(loc.segment_seq, loc.offset)?;
        let decoded = decode_frame_v1(&frame)?;
        if decoded.header_bytes.len() < 32 {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "stored frame header_bytes too small".to_string(),
            });
        }

        let canonical_len = decoded.header_bytes.len() - 32;
        let canonical_bytes = &decoded.header_bytes[..canonical_len];
        let header_hash = compute_header_hash(canonical_bytes);
        let payload_hash = compute_payload_hash(&decoded.payload_bytes);

        // Sanity: verify canonical parses (helps detect format drift).
        let header =
            decode_canonical_header_bytes_v1(canonical_bytes).map_err(|e| StorageError::ManifestRecordInvalid {
                msg: format!("failed to parse stored canonical header bytes: {e}"),
            })?;

        Ok((header, payload_hash, header_hash))
    }

    pub(crate) fn append_manifest_add_segment(&mut self, seg: &SegmentMeta) -> Result<()> {
        self.append_manifest_add_segment_with_stats(seg, None)
    }

    pub(crate) fn append_manifest_add_segment_with_stats(
        &mut self,
        seg: &SegmentMeta,
        stats: Option<&mut AppendStatsV1>,
    ) -> Result<()> {
        let rec = encode_manifest_add_segment_v1(seg)?;
        let framed = frame_manifest_record(&rec);

        self.append_manifest_framed_with_stats(&framed, stats)
    }

    pub(crate) fn append_manifest_framed(&mut self, framed: &[u8]) -> Result<()> {
        self.append_manifest_framed_with_stats(framed, None)
    }

    pub(crate) fn append_manifest_framed_with_stats(
        &mut self,
        framed: &[u8],
        stats: Option<&mut AppendStatsV1>,
    ) -> Result<()> {
        // Manifest is control-plane state (small, append-only). Keep it on a plain fsync() path
        // so gpu-gds can remain strict about 4KiB alignment for segment IO without forcing a
        // manifest format/version bump.
        self.manifest.seek(SeekFrom::Start(self.manifest_end)).map_err(io_err)?;
        self.manifest.write_all(framed).map_err(io_err)?;
        let fence_fsync_start = std::time::Instant::now();
        self.manifest.sync_all().map_err(io_err)?;
        if let Some(s) = stats {
            s.add_fence_fsync_elapsed(fence_fsync_start.elapsed());
        }

        self.manifest_end += framed.len() as u64;
        Ok(())
    }

    pub(crate) fn append_manifest_add_dir_run(&mut self, run: &DirRunMeta) -> Result<()> {
        let rec = encode_manifest_add_dir_run_v1(self.shard_id, self.epoch, run)?;
        let framed = frame_manifest_record(&rec);
        self.append_manifest_framed(&framed)
    }

    pub(crate) fn append_manifest_remove_dir_run(&mut self, key: DirRunKey) -> Result<()> {
        let rec = encode_manifest_remove_dir_run_v1(key);
        let framed = frame_manifest_record(&rec);
        self.append_manifest_framed(&framed)
    }

    pub(crate) fn append_manifest_stream_meta_update(&mut self, upd: StreamMetaUpdateV1) -> Result<()> {
        let rec = encode_manifest_stream_meta_update_v1(upd);
        let framed = frame_manifest_record(&rec);
        self.append_manifest_framed(&framed)
    }

    pub(crate) fn stream_cut_seq(&self, stream_hash: u64) -> u64 {
        let m = self.stream_meta.get(&stream_hash).copied().unwrap_or_default();
        m.min_live_seq.max(m.tombstone_seq)
    }

    pub(crate) fn filter_extents_live(&self, extents: &[DirExtentV1]) -> Vec<DirExtentV1> {
        let mut out: Vec<DirExtentV1> = Vec::with_capacity(extents.len());
        for &e in extents {
            let cut = self.stream_cut_seq(e.stream_hash);
            if e.max_seq < cut {
                continue;
            }
            out.push(e);
        }
        out
    }

    pub(crate) fn publish_dir_run_v1(
        &mut self,
        key: DirRunKey,
        created_at_unix_ns: u64,
        extents: &[DirExtentV1],
    ) -> Result<Option<DirRunMeta>> {
        if extents.is_empty() {
            return Ok(None);
        }
        let bytes = encode_dir_run_v1(created_at_unix_ns, extents)?;
        // Phase 12 hardening:
        // avoid aborting append/compaction when a stale on-disk dirrun path already exists.
        // Keep run-id resolution deterministic by incrementing within the same level.
        let mut run_id = key.run_id;
        for _ in 0..1024 {
            let candidate_key = DirRunKey {
                level: key.level,
                run_id,
            };

            if self.dir_runs.contains_key(&candidate_key) {
                run_id = run_id.wrapping_add(1);
                continue;
            }

            let tmp_rel = format!(
                "tmp/dirrun-l{}-r{:020}.partial",
                candidate_key.level, candidate_key.run_id
            );
            let final_rel = dir_run_relative_path_v1(candidate_key.level, candidate_key.run_id);
            let tmp_path = self.paths.shard_dir.join(&tmp_rel);
            let final_path = self.paths.shard_dir.join(&final_rel);

            if final_path.exists() {
                run_id = run_id.wrapping_add(1);
                continue;
            }

            // Defensive cleanup of abandoned tmp files from interrupted runs.
            if tmp_path.exists() {
                let _ = std::fs::remove_file(&tmp_path);
            }

            write_new_file_host(&tmp_path, &bytes)?;

            std::fs::rename(&tmp_path, &final_path).map_err(io_err)?;
            fsync_dir(&self.paths.directory_dir)?;

            let meta = DirRunMeta {
                key: candidate_key,
                relative_path: final_rel,
                file_len: bytes.len() as u64,
                created_at_unix_ns,
                record_count: extents.len() as u64,
            };

            self.append_manifest_add_dir_run(&meta)?;
            self.dir_runs.insert(candidate_key, meta.clone());
            return Ok(Some(meta));
        }

        Err(StorageError::ManifestRecordInvalid {
            msg: format!(
                "unable to allocate dirrun output path after collision retries (level={}, run_id_start={})",
                key.level, key.run_id
            ),
        })
    }

    /// Rebuild the stream directory from the manifest's directory runs.
    ///
    /// An extent naming a segment the manifest no longer carries is a **miss**,
    /// not corruption. Reclaim (tenant erasure) retires a segment together with
    /// the L0 run whose `run_id` equals its `segment_seq`, but that pair is not
    /// the whole story: a seal publishes its run from the *live* extent set, so
    /// a later segment's L0 run routinely carries extents for earlier segments
    /// (and directory compaction merges extents across segments besides). Those
    /// runs outlive the reclaimed segment by design — the manifest is
    /// append-only and published runs are never rewritten.
    ///
    /// Erroring on such an extent fails `ShardStorage::open`, and open is on the
    /// path of every write while reads scan `segments/` directly. The result is
    /// the silent-500 signature this store has hit twice: all ingest returning
    /// 500 with `/readyz` green, unrecoverable without an offline manifest
    /// repair (see `corecruxctl storage repair-manifest`, which cannot see this
    /// class at all because the segment is already out of the manifest). One
    /// erasure with `reclaim: true` was enough to wedge host `crux` both times.
    ///
    /// So: skip the extent, count it, and say so once per run. The directory is
    /// a lookup index — an entry that resolves to nothing is a miss, and the
    /// read path already treats an absent directory entry as one.
    pub(crate) fn rebuild_directory_from_runs(&mut self) -> Result<HashSet<u64>> {
        let mut present_segments: HashSet<u64> = HashSet::new();
        let mut out: HashMap<u64, Vec<StreamSegmentRef>> = HashMap::new();

        let mut runs: Vec<DirRunMeta> = self.dir_runs.values().cloned().collect();
        runs.sort_by(|a, b| {
            a.key
                .level
                .cmp(&b.key.level)
                .then_with(|| a.key.run_id.cmp(&b.key.run_id))
        });

        for run in runs {
            let path = self.paths.shard_dir.join(&run.relative_path);
            let bytes = std::fs::read(&path).map_err(io_err)?;
            let decoded = decode_dir_run_v1(&bytes)?;

            if decoded.file_len != run.file_len {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: format!("dirrun file_len mismatch for {}", run.relative_path),
                });
            }
            if decoded.record_count != run.record_count {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: format!("dirrun record_count mismatch for {}", run.relative_path),
                });
            }
            if decoded.created_at_unix_ns != run.created_at_unix_ns {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: format!("dirrun created_at mismatch for {}", run.relative_path),
                });
            }

            let mut retired_extents = 0usize;
            for part in decoded.partitions {
                for e in part {
                    if !self.segments_by_seq.contains_key(&e.segment_seq) {
                        retired_extents += 1;
                        continue;
                    }

                    let cut = self.stream_cut_seq(e.stream_hash);
                    if e.max_seq < cut {
                        continue;
                    }

                    out.entry(e.stream_hash).or_default().push(StreamSegmentRef {
                        segment_seq: e.segment_seq,
                        min_seq: e.min_seq,
                        max_seq: e.max_seq,
                    });
                    present_segments.insert(e.segment_seq);
                }
            }
            if retired_extents > 0 {
                tracing::info!(
                    run_level = run.key.level,
                    run_id = run.key.run_id,
                    retired_extents,
                    "dirrun-extents-skipped: directory run names segments the manifest has retired"
                );
            }
        }

        for refs in out.values_mut() {
            refs.sort_by_key(|r| r.segment_seq);
        }
        self.directory_by_stream = out;
        Ok(present_segments)
    }

    pub(crate) fn bootstrap_directory_runs_on_open(
        &mut self,
        extents_by_segment: &HashMap<u64, Vec<DirExtentV1>>,
    ) -> Result<()> {
        // Ensure we have at least L0 runs for any sealed segments that are missing from directory
        // state (e.g. crash between AddSegment and AddDirRun records, or older data dirs).
        if self.dir_runs.is_empty() && !self.segments_in_order.is_empty() {
            let segs: Vec<(u64, u64)> = self
                .segments_in_order
                .iter()
                .map(|s| (s.segment_seq, s.sealed_at_unix_ns))
                .collect();
            for (segment_seq, sealed_at_unix_ns) in segs {
                let extents = extents_by_segment.get(&segment_seq).map_or(&[][..], |v| v.as_slice());
                let live = self.filter_extents_live(extents);
                let key = DirRunKey {
                    level: 0,
                    run_id: segment_seq,
                };
                let _ = self.publish_dir_run_v1(key, sealed_at_unix_ns, &live)?;
            }
        }

        let present = self.rebuild_directory_from_runs()?;

        let segs: Vec<(u64, u64)> = self
            .segments_in_order
            .iter()
            .map(|s| (s.segment_seq, s.sealed_at_unix_ns))
            .collect();
        for (segment_seq, sealed_at_unix_ns) in segs {
            if present.contains(&segment_seq) {
                continue;
            }
            let extents = extents_by_segment.get(&segment_seq).map_or(&[][..], |v| v.as_slice());
            let live = self.filter_extents_live(extents);
            if live.is_empty() {
                continue;
            }
            let key = DirRunKey {
                level: 0,
                run_id: segment_seq,
            };
            if self.dir_runs.contains_key(&key) {
                continue;
            }
            let _ = self.publish_dir_run_v1(key, sealed_at_unix_ns, &live)?;
        }

        let _ = self.rebuild_directory_from_runs()?;
        Ok(())
    }

    pub fn update_stream_meta(
        &mut self,
        stream_hash: u64,
        min_live_seq: u64,
        tombstone_seq: u64,
    ) -> Result<(u64, u64)> {
        let cur = self.stream_meta.get(&stream_hash).copied().unwrap_or_default();
        if min_live_seq != 0 && min_live_seq < cur.min_live_seq {
            return Err(StorageError::InvalidArgument {
                code: "CHECKPOINT_NON_MONOTONIC".to_string(),
                msg: format!(
                    "min_live_seq must be monotonic (current={}, requested={})",
                    cur.min_live_seq, min_live_seq
                ),
            });
        }
        if tombstone_seq != 0 && tombstone_seq < cur.tombstone_seq {
            return Err(StorageError::InvalidArgument {
                code: "TOMBSTONE_NON_MONOTONIC".to_string(),
                msg: format!(
                    "tombstone_seq must be monotonic (current={}, requested={})",
                    cur.tombstone_seq, tombstone_seq
                ),
            });
        }

        let next_min_live_seq = cur.min_live_seq.max(min_live_seq);
        let next_tombstone_seq = cur.tombstone_seq.max(tombstone_seq);

        if next_min_live_seq == cur.min_live_seq && next_tombstone_seq == cur.tombstone_seq {
            return Ok((cur.min_live_seq, cur.tombstone_seq));
        }

        let upd = StreamMetaUpdateV1 {
            stream_hash,
            min_live_seq: next_min_live_seq,
            tombstone_seq: next_tombstone_seq,
            gen: now_unix_ns(),
        };
        self.append_manifest_stream_meta_update(upd)?;

        let cut = {
            let e = self.stream_meta.entry(stream_hash).or_default();
            e.min_live_seq = next_min_live_seq;
            e.tombstone_seq = next_tombstone_seq;
            e.min_live_seq.max(e.tombstone_seq)
        };

        // Drop fully-dead extents from the in-memory directory for this stream (best-effort).
        if let Some(refs) = self.directory_by_stream.get_mut(&stream_hash) {
            refs.retain(|r| r.max_seq >= cut);
        }

        let e = self.stream_meta.get(&stream_hash).copied().unwrap_or_default();
        Ok((e.min_live_seq, e.tombstone_seq))
    }

    pub fn stream_meta_v1(&self, stream_hash: u64) -> (u64, u64) {
        let m = self.stream_meta.get(&stream_hash).copied().unwrap_or_default();
        (m.min_live_seq, m.tombstone_seq)
    }
}
