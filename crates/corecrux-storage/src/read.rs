// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Read path — tail locators, range scans, frame batch reads, replay cursors, stream-range index lookups.

use super::{
    add_selected_entries_stats, block_logical_starts, decode_stored_event_from_frame_bytes, frame_len_at, io_err,
    logical_offset_to_block, read_blocks_cpu, read_frame_bytes_physical, read_selected_frames_codec_none_from_entries,
    select_stream_range_from_trailer_sorted, select_stream_tail_from_trailer_bloom,
    select_stream_tail_from_trailer_sorted_from_seq_with_range, toc_lower_bound, toc_stream_range, FrameLocation,
    HeadFrameMeta, ReadFrameBatchPackedV1, ReadStatsV1, ReplayCursor, ReplayFrames, Result, SegmentMeta, ShardStorage,
    StorageError, StoredEvent, StreamTailLocator, StreamTailLocatorEntry, StreamTailPointer, StreamTailPointerGroup,
    STREAM_TAIL_LOCATOR_MAX_EVENTS,
};
use corecrux_segment::{decode_frame_v1, decode_segment_v1, TocByOffsetEntryV1, TrailerIndexV1};
use std::collections::{HashMap, HashSet};
use std::fs::File;

impl ShardStorage {
    #[allow(clippy::unnecessary_wraps)] // Result return kept for caller ergonomics with `?` chains
    pub(crate) fn rebuild_tail_locator_from_directory(&mut self) -> Result<()> {
        self.tail_locator_by_stream.clear();
        self.tail_pointer_by_stream.clear();
        let mut pointer_rebuild_streams: Vec<u64> = Vec::new();
        for (&stream_hash, refs) in &self.directory_by_stream {
            let cut = self.stream_cut_seq(stream_hash);
            let mut desc: Vec<StreamTailLocatorEntry> = Vec::new();
            for r in refs.iter().rev() {
                if desc.len() >= STREAM_TAIL_LOCATOR_MAX_EVENTS {
                    break;
                }
                if r.max_seq < cut {
                    continue;
                }
                let Some(ti) = self.segment_trailers_by_seq.get(&r.segment_seq) else {
                    continue;
                };
                let need = STREAM_TAIL_LOCATOR_MAX_EVENTS.saturating_sub(desc.len());
                let range_hint = self
                    .segment_stream_ranges_by_seq
                    .get(&r.segment_seq)
                    .and_then(|m| m.get(&stream_hash))
                    .copied()
                    .map(|(a, b)| (a as usize, b as usize));
                let mut selected =
                    select_stream_tail_from_trailer_sorted_from_seq_with_range(ti, range_hint, stream_hash, cut, need);
                selected.retain(|e| e.seq >= cut);
                for e in selected {
                    if desc.len() >= STREAM_TAIL_LOCATOR_MAX_EVENTS {
                        break;
                    }
                    desc.push(StreamTailLocatorEntry {
                        segment_seq: r.segment_seq,
                        entry: e,
                    });
                }
            }
            if desc.is_empty() {
                continue;
            }
            desc.reverse(); // keep ascending for stable append/update behavior
            self.tail_locator_by_stream
                .insert(stream_hash, StreamTailLocator { entries_asc: desc });
            pointer_rebuild_streams.push(stream_hash);
        }
        for stream_hash in pointer_rebuild_streams {
            self.rebuild_tail_pointer_for_stream(stream_hash);
        }
        Ok(())
    }

    pub(crate) fn rebuild_tail_pointer_for_stream(&mut self, stream_hash: u64) {
        let Some(locator) = self.tail_locator_by_stream.get(&stream_hash) else {
            self.tail_pointer_by_stream.remove(&stream_hash);
            return;
        };

        let mut entries_desc = locator.entries_asc.clone();
        entries_desc.reverse();
        let latest_segment_seq = entries_desc.first().map_or(0, |e| e.segment_seq);
        let latest_seq = entries_desc.first().map_or(0, |e| e.entry.seq);
        let mut grouped_desc: Vec<StreamTailPointerGroup> = Vec::new();
        for entry in &entries_desc {
            if let Some(group) = grouped_desc
                .iter_mut()
                .find(|group| group.segment_seq == entry.segment_seq)
            {
                group.entries_desc.push(entry.entry);
            } else {
                grouped_desc.push(StreamTailPointerGroup {
                    segment_seq: entry.segment_seq,
                    entries_desc: vec![entry.entry],
                });
            }
        }
        self.tail_pointer_by_stream.insert(
            stream_hash,
            StreamTailPointer {
                latest_segment_seq,
                latest_seq,
                entries_desc,
                grouped_desc,
            },
        );
    }

    pub(crate) fn locator_tail_segments_desc(
        &self,
        stream_hash: u64,
        cut: u64,
        limit: usize,
    ) -> (Vec<(u64, Vec<TocByOffsetEntryV1>)>, bool) {
        if limit == 0 {
            return (Vec::new(), false);
        }

        if let Some(ptr) = self.tail_pointer_by_stream.get(&stream_hash) {
            if cut <= ptr.latest_seq {
                let mut groups: Vec<(u64, Vec<TocByOffsetEntryV1>)> = Vec::new();
                let mut taken = 0usize;
                for g in &ptr.grouped_desc {
                    if taken >= limit {
                        break;
                    }
                    let mut selected: Vec<TocByOffsetEntryV1> = Vec::new();
                    for entry in &g.entries_desc {
                        if entry.seq < cut {
                            continue;
                        }
                        selected.push(*entry);
                        taken = taken.saturating_add(1);
                        if taken >= limit {
                            break;
                        }
                    }
                    if !selected.is_empty() {
                        groups.push((g.segment_seq, selected));
                    }
                }
                return (groups, taken >= limit);
            }
        }

        let mut groups: Vec<(u64, Vec<TocByOffsetEntryV1>)> = Vec::new();
        let mut taken = 0usize;
        for e in self.locator_tail_entries_desc(stream_hash, cut, limit) {
            if taken >= limit {
                break;
            }
            if e.entry.seq < cut {
                continue;
            }
            if let Some(group) = groups.iter_mut().find(|(segment_seq, _)| *segment_seq == e.segment_seq) {
                group.1.push(e.entry);
            } else {
                groups.push((e.segment_seq, vec![e.entry]));
            }
            taken = taken.saturating_add(1);
        }
        (groups, taken >= limit)
    }

    pub(crate) fn update_tail_locator_for_stream_entries(
        &mut self,
        stream_hash: u64,
        segment_seq: u64,
        entries_asc: &[TocByOffsetEntryV1],
    ) {
        if entries_asc.is_empty() {
            return;
        }
        let locator = self
            .tail_locator_by_stream
            .entry(stream_hash)
            .or_insert(StreamTailLocator {
                entries_asc: Vec::new(),
            });
        locator.entries_asc.extend(
            entries_asc
                .iter()
                .copied()
                .map(|entry| StreamTailLocatorEntry { segment_seq, entry }),
        );
        if locator.entries_asc.len() > STREAM_TAIL_LOCATOR_MAX_EVENTS {
            let drop_n = locator.entries_asc.len().saturating_sub(STREAM_TAIL_LOCATOR_MAX_EVENTS);
            locator.entries_asc.drain(0..drop_n);
        }
        self.rebuild_tail_pointer_for_stream(stream_hash);
    }

    pub(crate) fn locator_tail_entries_desc(
        &self,
        stream_hash: u64,
        cut: u64,
        limit: usize,
    ) -> Vec<StreamTailLocatorEntry> {
        if limit == 0 {
            return Vec::new();
        }

        if let Some(ptr) = self.tail_pointer_by_stream.get(&stream_hash) {
            if cut <= ptr.latest_seq {
                let _latest_segment_seq = ptr.latest_segment_seq;
                let mut out: Vec<StreamTailLocatorEntry> = Vec::with_capacity(limit.min(ptr.entries_desc.len()));
                for e in &ptr.entries_desc {
                    if e.entry.seq < cut {
                        continue;
                    }
                    out.push(*e);
                    if out.len() >= limit {
                        break;
                    }
                }
                return out;
            }
        }

        let Some(locator) = self.tail_locator_by_stream.get(&stream_hash) else {
            return Vec::new();
        };
        let mut out: Vec<StreamTailLocatorEntry> = Vec::with_capacity(limit.min(locator.entries_asc.len()));
        for e in locator.entries_asc.iter().rev() {
            if e.entry.seq < cut {
                continue;
            }
            out.push(*e);
            if out.len() >= limit {
                break;
            }
        }
        out
    }

    pub(crate) fn read_selected_tail_entries_from_trailer(
        &self,
        seg: &SegmentMeta,
        ti: &TrailerIndexV1,
        selected: &[TocByOffsetEntryV1],
        stats: &mut ReadStatsV1,
        out: &mut Vec<StoredEvent>,
        limit: usize,
    ) -> Result<()> {
        if selected.is_empty() {
            return Ok(());
        }

        let seg_path = self.paths.shard_dir.join(&seg.relative_path);
        let file_fallback: File;
        let file_ref: &File = if let Some(cached) = self.segment_files_by_seq.get(&seg.segment_seq) {
            cached
        } else {
            file_fallback = File::open(&seg_path).map_err(io_err)?;
            &file_fallback
        };
        stats.segments_touched = stats.segments_touched.saturating_add(1);
        let estimated_disk_bytes = add_selected_entries_stats(stats, &ti.blocks, selected)?;
        let block_starts = block_logical_starts(&ti.blocks)?;
        let can_frame_window_read = selected.iter().all(|e| {
            let Some(meta) = ti.blocks.get(e.block_id as usize) else {
                return false;
            };
            meta.codec == corecrux_segment::RECORD_BLOCK_CODEC_NONE_V1 && meta.compressed_len == meta.uncompressed_len
        });

        if can_frame_window_read {
            let io_start = std::time::Instant::now();
            let read = read_selected_frames_codec_none_from_entries(file_ref, &ti.blocks, selected)?;
            stats.add_io_elapsed(io_start.elapsed());
            stats.disk_bytes_estimate = stats
                .disk_bytes_estimate
                .saturating_sub(estimated_disk_bytes)
                .saturating_add(read.disk_bytes_read);

            let decode_start = std::time::Instant::now();
            for (e, frame) in selected.iter().zip(read.frames.iter()) {
                let bid = e.block_id as usize;
                let block_start = block_starts
                    .get(bid)
                    .copied()
                    .ok_or(StorageError::ManifestRecordInvalid {
                        msg: "block start missing".to_string(),
                    })?;
                let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                    .checked_add(block_start)
                    .and_then(|v| v.checked_add(e.in_block_offset as u64))
                    .ok_or(StorageError::ManifestRecordInvalid {
                        msg: "frame offset overflow".to_string(),
                    })?;

                let ev = decode_stored_event_from_frame_bytes(
                    self.shard_id as u64,
                    seg.epoch,
                    seg.segment_seq,
                    frame_off,
                    frame,
                )?;
                out.push(ev);
                if out.len() >= limit {
                    break;
                }
            }
            stats.add_decode_elapsed(decode_start.elapsed());
        } else {
            let mut block_ids: Vec<u32> = selected.iter().map(|e| e.block_id).collect();
            block_ids.sort_unstable();
            block_ids.dedup();

            let io_start = std::time::Instant::now();
            let blocks = read_blocks_cpu(file_ref, &ti.blocks, &block_ids)?;
            stats.add_io_elapsed(io_start.elapsed());

            let decode_start = std::time::Instant::now();
            for e in selected {
                let bid = e.block_id as usize;
                let Some(buf) = blocks.get(bid).and_then(|v| v.as_ref()) else {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: "block buffer missing".to_string(),
                    });
                };
                let start = e.in_block_offset as usize;
                let len = e.frame_len as usize;
                let end = start.checked_add(len).ok_or(StorageError::ManifestRecordInvalid {
                    msg: "frame slice overflow".to_string(),
                })?;
                if end > buf.len() {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: "frame points outside uncompressed block".to_string(),
                    });
                }
                let block_start = block_starts
                    .get(bid)
                    .copied()
                    .ok_or(StorageError::ManifestRecordInvalid {
                        msg: "block start missing".to_string(),
                    })?;
                let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                    .checked_add(block_start)
                    .and_then(|v| v.checked_add(e.in_block_offset as u64))
                    .ok_or(StorageError::ManifestRecordInvalid {
                        msg: "frame offset overflow".to_string(),
                    })?;

                let ev = decode_stored_event_from_frame_bytes(
                    self.shard_id as u64,
                    seg.epoch,
                    seg.segment_seq,
                    frame_off,
                    &buf[start..end],
                )?;
                out.push(ev);
                if out.len() >= limit {
                    break;
                }
            }
            stats.add_decode_elapsed(decode_start.elapsed());
        }

        Ok(())
    }

    pub fn read_stream(
        &self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        stream_hash: u64,
        from_seq_inclusive: u64,
        max_events: u32,
    ) -> Result<Vec<StoredEvent>> {
        Ok(self
            .read_stream_with_stats(
                tenant_id,
                stream_type,
                stream_id,
                stream_hash,
                from_seq_inclusive,
                max_events,
            )?
            .0)
    }

    pub fn read_stream_with_stats(
        &self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        stream_hash: u64,
        from_seq_inclusive: u64,
        max_events: u32,
    ) -> Result<(Vec<StoredEvent>, ReadStatsV1)> {
        let _ = (tenant_id, stream_type, stream_id);
        let from_seq_inclusive = from_seq_inclusive.max(self.stream_cut_seq(stream_hash));
        let limit = if max_events == 0 {
            usize::MAX
        } else {
            max_events as usize
        };

        let mut stats = ReadStatsV1::default();
        let mut out: Vec<StoredEvent> = Vec::new();
        if let Some(refs) = self.directory_by_stream.get(&stream_hash) {
            for r in refs {
                if r.max_seq < from_seq_inclusive {
                    continue;
                }
                let seg =
                    self.segments_by_seq
                        .get(&r.segment_seq)
                        .ok_or_else(|| StorageError::ManifestRecordInvalid {
                            msg: "segment referenced by directory missing from segments_by_seq".to_string(),
                        })?;

                let seg_path = self.paths.shard_dir.join(&seg.relative_path);
                if let Some(ti) = self.segment_trailers_by_seq.get(&r.segment_seq) {
                    let file = File::open(&seg_path).map_err(io_err)?;
                    let remaining = limit.saturating_sub(out.len());
                    let selected =
                        select_stream_range_from_trailer_sorted(ti, stream_hash, from_seq_inclusive, remaining);
                    if selected.is_empty() {
                        continue;
                    }
                    stats.segments_touched = stats.segments_touched.saturating_add(1);

                    let block_starts = block_logical_starts(&ti.blocks)?;
                    let mut block_ids: Vec<u32> = selected.iter().map(|e| e.block_id).collect();
                    block_ids.sort_unstable();
                    block_ids.dedup();

                    let blocks = read_blocks_cpu(&file, &ti.blocks, &block_ids)?;

                    for e in selected {
                        let bid = e.block_id as usize;
                        let Some(buf) = blocks.get(bid).and_then(|v| v.as_ref()) else {
                            return Err(StorageError::ManifestRecordInvalid {
                                msg: "block buffer missing".to_string(),
                            });
                        };
                        let start = e.in_block_offset as usize;
                        let len = e.frame_len as usize;
                        let end = start.checked_add(len).ok_or(StorageError::ManifestRecordInvalid {
                            msg: "frame slice overflow".to_string(),
                        })?;
                        if end > buf.len() {
                            return Err(StorageError::ManifestRecordInvalid {
                                msg: "frame points outside uncompressed block".to_string(),
                            });
                        }
                        let block_start =
                            block_starts
                                .get(bid)
                                .copied()
                                .ok_or(StorageError::ManifestRecordInvalid {
                                    msg: "block start missing".to_string(),
                                })?;
                        let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                            .checked_add(block_start)
                            .and_then(|v| v.checked_add(e.in_block_offset as u64))
                            .ok_or(StorageError::ManifestRecordInvalid {
                                msg: "frame offset overflow".to_string(),
                            })?;

                        let ev = decode_stored_event_from_frame_bytes(
                            self.shard_id as u64,
                            seg.epoch,
                            seg.segment_seq,
                            frame_off,
                            &buf[start..end],
                        )?;
                        out.push(ev);
                        if out.len() >= limit {
                            return Ok((out, stats));
                        }
                    }

                    continue;
                }

                // Fallback: Phase 2 reader (no trailer indexes present).
                let bytes = std::fs::read(&seg_path).map_err(io_err)?;
                let (_h, _toc_h, entries, _f) = decode_segment_v1(&bytes)?;

                let start = toc_lower_bound(&entries, stream_hash, from_seq_inclusive);
                let mut touched = false;
                for e in entries.iter().skip(start) {
                    if e.stream_hash != stream_hash {
                        break;
                    }
                    let off = e.file_offset as usize;
                    let len = e.frame_len as usize;
                    if off.saturating_add(len) > bytes.len() {
                        return Err(StorageError::ManifestRecordInvalid {
                            msg: "toc frame points outside file".to_string(),
                        });
                    }

                    let frame_off = e.file_offset as u64;
                    let ev = decode_stored_event_from_frame_bytes(
                        self.shard_id as u64,
                        seg.epoch,
                        seg.segment_seq,
                        frame_off,
                        &bytes[off..off + len],
                    )?;
                    if !touched {
                        stats.segments_touched = stats.segments_touched.saturating_add(1);
                        touched = true;
                    }
                    out.push(ev);
                    if out.len() >= limit {
                        return Ok((out, stats));
                    }
                }
            }
        }

        // Head segment support: include not-yet-sealed bytes (Phase 5).
        if out.len() < limit {
            if let Some(head) = self.head.as_ref() {
                let Some((_min, max)) = head.stream_min_max.get(&stream_hash) else {
                    return Ok((out, stats));
                };
                if *max >= from_seq_inclusive {
                    let remaining = limit.saturating_sub(out.len());
                    let selected: Vec<&HeadFrameMeta> = head
                        .frames
                        .iter()
                        .filter(|f| f.stream_hash == stream_hash && f.seq >= from_seq_inclusive)
                        .take(remaining)
                        .collect();
                    if !selected.is_empty() {
                        stats.segments_touched = stats.segments_touched.saturating_add(1);
                        let mut block_ids: Vec<u32> = selected.iter().map(|f| f.block_id).collect();
                        block_ids.sort_unstable();
                        block_ids.dedup();

                        let blocks = read_blocks_cpu(&head.file, &head.blocks, &block_ids)?;

                        for f in selected {
                            let bid = f.block_id as usize;
                            let Some(buf) = blocks.get(bid).and_then(|v| v.as_ref()) else {
                                return Err(StorageError::ManifestRecordInvalid {
                                    msg: "head block buffer missing".to_string(),
                                });
                            };
                            let start = f.in_block_offset as usize;
                            let len = f.frame_len as usize;
                            let end = start.checked_add(len).ok_or(StorageError::ManifestRecordInvalid {
                                msg: "head frame slice overflow".to_string(),
                            })?;
                            if end > buf.len() {
                                return Err(StorageError::ManifestRecordInvalid {
                                    msg: "head frame points outside uncompressed block".to_string(),
                                });
                            }

                            let frame_off =
                                (corecrux_segment::SEGMENT_HEADER_LEN as u64).saturating_add(f.record_off as u64);
                            let ev = decode_stored_event_from_frame_bytes(
                                self.shard_id as u64,
                                self.epoch,
                                head.segment_seq,
                                frame_off,
                                &buf[start..end],
                            )?;
                            out.push(ev);
                            if out.len() >= limit {
                                break;
                            }
                        }
                    }
                }
            }
        }
        Ok((out, stats))
    }

    pub fn read_tail(
        &self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        stream_hash: u64,
        tail_events: u32,
    ) -> Result<Vec<StoredEvent>> {
        Ok(self
            .read_tail_with_stats(tenant_id, stream_type, stream_id, stream_hash, tail_events)?
            .0)
    }

    pub fn read_tail_with_stats(
        &self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        stream_hash: u64,
        tail_events: u32,
    ) -> Result<(Vec<StoredEvent>, ReadStatsV1)> {
        let _ = (tenant_id, stream_type, stream_id);
        let cut = self.stream_cut_seq(stream_hash);
        let limit = tail_events as usize;
        if limit == 0 {
            return Ok((Vec::new(), ReadStatsV1::default()));
        }

        let total_start = std::time::Instant::now();
        let mut stats = ReadStatsV1::default();
        let mut out: Vec<StoredEvent> = Vec::new();
        // Head segment support: tail begins at the currently-appending segment.
        if let Some(head) = self.head.as_ref() {
            if head.stream_min_max.contains_key(&stream_hash) {
                let index_start = std::time::Instant::now();
                let remaining = limit.saturating_sub(out.len());
                let mut selected_idx_desc: Vec<usize> = Vec::new();
                let mut used_fastpath = false;

                if let Some(tail_idx) = head.stream_tail_idx_by_stream.get(&stream_hash) {
                    used_fastpath = true;
                    for ref_entry in tail_idx.iter().rev() {
                        stats.head_frames_scanned = stats.head_frames_scanned.saturating_add(1);
                        if ref_entry.seq < cut {
                            continue;
                        }
                        if ref_entry.frame_idx >= head.frames.len() {
                            continue;
                        }
                        selected_idx_desc.push(ref_entry.frame_idx);
                        if selected_idx_desc.len() >= remaining {
                            break;
                        }
                    }
                }

                if used_fastpath {
                    stats.head_tail_fastpath_hits = stats.head_tail_fastpath_hits.saturating_add(1);
                } else {
                    stats.head_tail_fastpath_misses = stats.head_tail_fastpath_misses.saturating_add(1);
                }

                if selected_idx_desc.len() < remaining {
                    let mut seen: HashSet<usize> = selected_idx_desc.iter().copied().collect();
                    for (idx, f) in head.frames.iter().enumerate().rev() {
                        stats.head_frames_scanned = stats.head_frames_scanned.saturating_add(1);
                        if f.stream_hash != stream_hash || f.seq < cut {
                            continue;
                        }
                        if !seen.insert(idx) {
                            continue;
                        }
                        selected_idx_desc.push(idx);
                        if selected_idx_desc.len() >= remaining {
                            break;
                        }
                    }
                }

                let selected: Vec<&HeadFrameMeta> = selected_idx_desc
                    .iter()
                    .filter_map(|idx| head.frames.get(*idx))
                    .collect();
                stats.add_index_elapsed(index_start.elapsed());

                if !selected.is_empty() {
                    stats.segments_touched = stats.segments_touched.saturating_add(1);
                    let mut entries: Vec<TocByOffsetEntryV1> = Vec::with_capacity(selected.len());
                    for f in &selected {
                        entries.push(TocByOffsetEntryV1 {
                            stream_hash: f.stream_hash,
                            seq: f.seq,
                            block_id: f.block_id,
                            in_block_offset: f.in_block_offset,
                            frame_len: f.frame_len,
                            flags: 0,
                            event_id_hash16: f.event_id_hash16,
                            header_digest8: f.header_digest8,
                            payload_digest8: f.payload_digest8,
                        });
                    }
                    let estimated_disk_bytes = add_selected_entries_stats(&mut stats, &head.blocks, &entries)?;
                    let can_frame_window_read = selected.iter().all(|f| {
                        let Some(meta) = head.blocks.get(f.block_id as usize) else {
                            return false;
                        };
                        meta.codec == corecrux_segment::RECORD_BLOCK_CODEC_NONE_V1
                            && meta.compressed_len == meta.uncompressed_len
                    });
                    if can_frame_window_read {
                        let io_start = std::time::Instant::now();
                        let read = read_selected_frames_codec_none_from_entries(&head.file, &head.blocks, &entries)?;
                        stats.add_io_elapsed(io_start.elapsed());
                        stats.disk_bytes_estimate = stats
                            .disk_bytes_estimate
                            .saturating_sub(estimated_disk_bytes)
                            .saturating_add(read.disk_bytes_read);

                        let decode_start = std::time::Instant::now();
                        for (f, frame) in selected.iter().zip(read.frames.iter()) {
                            let frame_off =
                                (corecrux_segment::SEGMENT_HEADER_LEN as u64).saturating_add(f.record_off as u64);
                            let ev = decode_stored_event_from_frame_bytes(
                                self.shard_id as u64,
                                self.epoch,
                                head.segment_seq,
                                frame_off,
                                frame,
                            )?;
                            out.push(ev);
                            if out.len() >= limit {
                                break;
                            }
                        }
                        stats.add_decode_elapsed(decode_start.elapsed());
                    } else {
                        let mut block_ids: Vec<u32> = entries.iter().map(|e| e.block_id).collect();
                        block_ids.sort_unstable();
                        block_ids.dedup();

                        let io_start = std::time::Instant::now();
                        let blocks = read_blocks_cpu(&head.file, &head.blocks, &block_ids)?;
                        stats.add_io_elapsed(io_start.elapsed());

                        let decode_start = std::time::Instant::now();
                        for f in &selected {
                            let bid = f.block_id as usize;
                            let Some(buf) = blocks.get(bid).and_then(|v| v.as_ref()) else {
                                return Err(StorageError::ManifestRecordInvalid {
                                    msg: "head block buffer missing".to_string(),
                                });
                            };
                            let start = f.in_block_offset as usize;
                            let len = f.frame_len as usize;
                            let end = start.checked_add(len).ok_or(StorageError::ManifestRecordInvalid {
                                msg: "head frame slice overflow".to_string(),
                            })?;
                            if end > buf.len() {
                                return Err(StorageError::ManifestRecordInvalid {
                                    msg: "head frame points outside uncompressed block".to_string(),
                                });
                            }
                            let frame_off =
                                (corecrux_segment::SEGMENT_HEADER_LEN as u64).saturating_add(f.record_off as u64);
                            let ev = decode_stored_event_from_frame_bytes(
                                self.shard_id as u64,
                                self.epoch,
                                head.segment_seq,
                                frame_off,
                                &buf[start..end],
                            )?;
                            out.push(ev);
                            if out.len() >= limit {
                                break;
                            }
                        }
                        stats.add_decode_elapsed(decode_start.elapsed());
                    }
                }
            }
        }

        let Some(refs) = self.directory_by_stream.get(&stream_hash) else {
            out.reverse(); // ascending seq
            stats.total_nanos = total_start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            return Ok((out, stats));
        };
        let index_start = std::time::Instant::now();
        let (locator_selected_by_segment_desc, locator_can_fully_satisfy) =
            self.locator_tail_segments_desc(stream_hash, cut, limit);
        stats.add_index_elapsed(index_start.elapsed());
        if locator_can_fully_satisfy {
            stats.locator_fully_satisfied_hits = stats.locator_fully_satisfied_hits.saturating_add(1);
        } else {
            stats.locator_fully_satisfied_misses = stats.locator_fully_satisfied_misses.saturating_add(1);
        }

        // Fast path for cache-neutral tails: when the locator already has enough entries,
        // skip scanning directory refs entirely and read only locator-selected segments.
        if locator_can_fully_satisfy {
            for (seg_seq, mut selected) in locator_selected_by_segment_desc {
                if out.len() >= limit {
                    break;
                }
                let Some(seg) = self.segments_by_seq.get(&seg_seq) else {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: "segment referenced by locator missing from segments_by_seq".to_string(),
                    });
                };
                let Some(ti) = self.segment_trailers_by_seq.get(&seg_seq) else {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: "segment referenced by locator missing trailer index".to_string(),
                    });
                };
                let remaining = limit.saturating_sub(out.len());
                let index_start = std::time::Instant::now();
                if selected.len() > remaining {
                    selected.truncate(remaining);
                }
                selected.retain(|e| e.seq >= cut);
                stats.add_index_elapsed(index_start.elapsed());
                if selected.is_empty() {
                    continue;
                }
                self.read_selected_tail_entries_from_trailer(seg, ti, &selected, &mut stats, &mut out, limit)?;
            }
            out.reverse(); // ascending seq
            stats.total_nanos = total_start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            return Ok((out, stats));
        }

        let mut locator_desc_by_segment: HashMap<u64, Vec<TocByOffsetEntryV1>> =
            locator_selected_by_segment_desc.into_iter().collect();

        for r in refs.iter().rev() {
            if r.max_seq < cut {
                continue;
            }
            let seg = self
                .segments_by_seq
                .get(&r.segment_seq)
                .ok_or_else(|| StorageError::ManifestRecordInvalid {
                    msg: "segment referenced by directory missing from segments_by_seq".to_string(),
                })?;

            let seg_path = self.paths.shard_dir.join(&seg.relative_path);
            if let Some(ti) = self.segment_trailers_by_seq.get(&r.segment_seq) {
                let remaining = limit.saturating_sub(out.len());
                let index_start = std::time::Instant::now();
                let mut selected = locator_desc_by_segment.remove(&r.segment_seq).unwrap_or_default();
                if selected.len() > remaining {
                    selected.truncate(remaining);
                }
                if selected.len() < remaining && !locator_can_fully_satisfy {
                    let need = remaining.saturating_sub(selected.len());
                    let range_hint = self
                        .segment_stream_ranges_by_seq
                        .get(&r.segment_seq)
                        .and_then(|m| m.get(&stream_hash))
                        .copied()
                        .map(|(a, b)| (a as usize, b as usize));
                    let mut extra = select_stream_tail_from_trailer_sorted_from_seq_with_range(
                        ti,
                        range_hint,
                        stream_hash,
                        cut,
                        need,
                    );
                    if extra.is_empty() && need <= 128 {
                        // Keep bloom as fallback only. Sorted-index-first avoids reverse block scans
                        // for sparse streams in large blocks.
                        extra = select_stream_tail_from_trailer_bloom(ti, stream_hash, need)?;
                    }
                    extra.retain(|e| e.seq >= cut);
                    if selected.is_empty() {
                        selected = extra;
                    } else {
                        for e in extra {
                            if selected.iter().any(|s| s.seq == e.seq) {
                                continue;
                            }
                            selected.push(e);
                            if selected.len() >= remaining {
                                break;
                            }
                        }
                    }
                }
                selected.retain(|e| e.seq >= cut);
                stats.add_index_elapsed(index_start.elapsed());
                if selected.is_empty() {
                    continue;
                }
                self.read_selected_tail_entries_from_trailer(seg, ti, &selected, &mut stats, &mut out, limit)?;

                if out.len() >= limit {
                    break;
                }
                continue;
            }

            // Fallback: Phase 2 reader (no trailer indexes present).
            let io_start = std::time::Instant::now();
            let bytes = std::fs::read(&seg_path).map_err(io_err)?;
            stats.add_io_elapsed(io_start.elapsed());
            stats.disk_bytes_estimate = stats.disk_bytes_estimate.saturating_add(bytes.len() as u64);
            let index_start = std::time::Instant::now();
            let (_h, _toc_h, entries, _f) = decode_segment_v1(&bytes)?;
            let (start, end) = toc_stream_range(&entries, stream_hash);
            stats.add_index_elapsed(index_start.elapsed());
            if start == end {
                continue;
            }

            let decode_start = std::time::Instant::now();
            let mut idx = end;
            while idx > start && out.len() < limit {
                idx -= 1;
                let e = entries[idx];
                let off = e.file_offset as usize;
                let len = e.frame_len as usize;
                if off.saturating_add(len) > bytes.len() {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: "toc frame points outside file".to_string(),
                    });
                }

                let frame_off = e.file_offset as u64;
                let ev = decode_stored_event_from_frame_bytes(
                    self.shard_id as u64,
                    seg.epoch,
                    seg.segment_seq,
                    frame_off,
                    &bytes[off..off + len],
                )?;
                if ev.seq >= cut {
                    stats.frames_selected = stats.frames_selected.saturating_add(1);
                    stats.frame_bytes = stats.frame_bytes.saturating_add(len as u64);
                    out.push(ev);
                }
            }
            stats.add_decode_elapsed(decode_start.elapsed());

            if out.len() >= limit {
                break;
            }
        }

        out.reverse(); // ascending seq
        stats.total_nanos = total_start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        Ok((out, stats))
    }

    /// Replay frames from sealed segments only (manifest-committed).
    ///
    /// This is the correct source for derived state (e.g. projections) because the "head"
    /// segment is not crash-stable until it is sealed and referenced by the MANIFEST.
    #[tracing::instrument(
        level = "info",
        skip(self),
        fields(has_cursor = cursor.is_some(), max_frames)
    )]
    pub fn replay_from_sealed(
        &self,
        cursor: Option<ReplayCursor>,
        max_frames: u32,
    ) -> Result<(ReplayFrames, Option<ReplayCursor>)> {
        let limit = if max_frames == 0 {
            usize::MAX
        } else {
            max_frames as usize
        };

        let sealed_len = self.segments_in_order.len();
        if sealed_len == 0 {
            return Ok((Vec::new(), None));
        }

        let (mut seg_idx, mut offset) = match cursor {
            None => (0usize, corecrux_segment::SEGMENT_HEADER_LEN as u64),
            Some(c) => {
                if let Some(idx) = self
                    .segments_in_order
                    .iter()
                    .position(|s| s.segment_seq == c.segment_seq)
                {
                    (idx, c.offset)
                } else {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: format!("cursor segment_seq {} not found", c.segment_seq),
                    });
                }
            }
        };

        let mut out: ReplayFrames = Vec::new();
        while seg_idx < sealed_len && out.len() < limit {
            let seg = &self.segments_in_order[seg_idx];
            let seg_path = self.paths.shard_dir.join(&seg.relative_path);
            let record_end: u64;

            if let Some(ti) = self.segment_trailers_by_seq.get(&seg.segment_seq) {
                let block_starts = block_logical_starts(&ti.blocks)?;
                let total_uncompressed_len = ti
                    .blocks
                    .iter()
                    .try_fold(0u64, |acc, b| acc.checked_add(b.uncompressed_len as u64))
                    .ok_or(StorageError::ManifestRecordInvalid {
                        msg: "block uncompressed_len overflow".to_string(),
                    })?;
                record_end = (corecrux_segment::SEGMENT_HEADER_LEN as u64) + total_uncompressed_len;

                let file = File::open(&seg_path).map_err(io_err)?;
                let start_pos = ti.toc_by_offset.partition_point(|e| {
                    let bid = e.block_id as usize;
                    let Some(block_start) = block_starts.get(bid) else {
                        return true;
                    };
                    let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                        .saturating_add(*block_start)
                        .saturating_add(e.in_block_offset as u64);
                    frame_off < offset
                });

                if start_pos >= ti.toc_by_offset.len() {
                    seg_idx += 1;
                    offset = corecrux_segment::SEGMENT_HEADER_LEN as u64;
                    continue;
                }

                let remaining = limit.saturating_sub(out.len());
                let take = remaining.min(ti.toc_by_offset.len() - start_pos);
                let slice = &ti.toc_by_offset[start_pos..start_pos + take];
                let mut block_ids: Vec<u32> = slice.iter().map(|e| e.block_id).collect();
                block_ids.sort_unstable();
                block_ids.dedup();
                let blocks = read_blocks_cpu(&file, &ti.blocks, &block_ids)?;

                for e in slice {
                    if out.len() >= limit {
                        break;
                    }
                    let bid = e.block_id as usize;
                    let Some(buf) = blocks.get(bid).and_then(|v| v.as_ref()) else {
                        return Err(StorageError::ManifestRecordInvalid {
                            msg: "block buffer missing".to_string(),
                        });
                    };
                    let start = e.in_block_offset as usize;
                    let len = e.frame_len as usize;
                    let end = start.checked_add(len).ok_or(StorageError::ManifestRecordInvalid {
                        msg: "frame slice overflow".to_string(),
                    })?;
                    if end > buf.len() {
                        return Err(StorageError::ManifestRecordInvalid {
                            msg: "replay frame points outside uncompressed block".to_string(),
                        });
                    }

                    let block_start = block_starts
                        .get(bid)
                        .copied()
                        .ok_or(StorageError::ManifestRecordInvalid {
                            msg: "block start missing".to_string(),
                        })?;
                    let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                        .checked_add(block_start)
                        .and_then(|v| v.checked_add(e.in_block_offset as u64))
                        .ok_or(StorageError::ManifestRecordInvalid {
                            msg: "frame offset overflow".to_string(),
                        })?;

                    let frame = buf[start..end].to_vec();
                    let _ = decode_frame_v1(&frame)?;
                    let loc = FrameLocation {
                        shard_id: self.shard_id as u64,
                        epoch: seg.epoch,
                        segment_seq: seg.segment_seq,
                        offset: frame_off,
                    };
                    out.push((loc, frame));
                    offset = frame_off.saturating_add(e.frame_len as u64);
                }
            } else {
                // Fallback: Phase 2 scan.
                let bytes = std::fs::read(&seg_path).map_err(io_err)?;
                let (_h, _toc_h, _entries, footer) = decode_segment_v1(&bytes)?;
                let record_start = footer.record_area_offset;
                record_end = footer.toc_offset;

                if offset < record_start {
                    offset = record_start;
                }

                while offset < record_end && out.len() < limit {
                    let frame_len =
                        frame_len_at(&bytes, offset).ok_or_else(|| StorageError::ManifestRecordInvalid {
                            msg: "failed to compute frame length at replay cursor".to_string(),
                        })?;
                    let end = offset.saturating_add(frame_len as u64);
                    if end > record_end || end as usize > bytes.len() {
                        return Err(StorageError::ManifestRecordInvalid {
                            msg: "replay frame extends past record area".to_string(),
                        });
                    }

                    let frame = bytes[offset as usize..end as usize].to_vec();
                    let _ = decode_frame_v1(&frame)?;
                    let loc = FrameLocation {
                        shard_id: self.shard_id as u64,
                        epoch: seg.epoch,
                        segment_seq: seg.segment_seq,
                        offset,
                    };
                    out.push((loc, frame));
                    offset = end;
                }
            }

            if out.len() >= limit {
                if offset >= record_end {
                    seg_idx += 1;
                    if seg_idx >= sealed_len {
                        return Ok((out, None));
                    }
                    let next_seg = &self.segments_in_order[seg_idx];
                    return Ok((
                        out,
                        Some(ReplayCursor {
                            segment_seq: next_seg.segment_seq,
                            offset: corecrux_segment::SEGMENT_HEADER_LEN as u64,
                        }),
                    ));
                }
                return Ok((
                    out,
                    Some(ReplayCursor {
                        segment_seq: seg.segment_seq,
                        offset,
                    }),
                ));
            }

            seg_idx += 1;
            offset = corecrux_segment::SEGMENT_HEADER_LEN as u64;
        }

        Ok((out, None))
    }

    #[tracing::instrument(
        level = "info",
        skip(self),
        fields(has_cursor = cursor.is_some(), max_frames)
    )]
    pub fn replay_from(
        &self,
        cursor: Option<ReplayCursor>,
        max_frames: u32,
    ) -> Result<(ReplayFrames, Option<ReplayCursor>)> {
        let limit = if max_frames == 0 {
            usize::MAX
        } else {
            max_frames as usize
        };

        let sealed_len = self.segments_in_order.len();
        let has_head = self.head.is_some();
        let total_segments = sealed_len + usize::from(has_head);

        let (mut seg_idx, mut offset) = match cursor {
            None => {
                if sealed_len > 0 {
                    (0usize, corecrux_segment::SEGMENT_HEADER_LEN as u64)
                } else if has_head {
                    (sealed_len, corecrux_segment::SEGMENT_HEADER_LEN as u64)
                } else {
                    return Ok((Vec::new(), None));
                }
            }
            Some(c) => {
                if let Some(idx) = self
                    .segments_in_order
                    .iter()
                    .position(|s| s.segment_seq == c.segment_seq)
                {
                    (idx, c.offset)
                } else if let Some(head) = self.head.as_ref() {
                    if head.segment_seq == c.segment_seq {
                        (sealed_len, c.offset)
                    } else {
                        return Err(StorageError::ManifestRecordInvalid {
                            msg: format!("cursor segment_seq {} not found", c.segment_seq),
                        });
                    }
                } else {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: format!("cursor segment_seq {} not found", c.segment_seq),
                    });
                }
            }
        };

        let mut out: ReplayFrames = Vec::new();
        while seg_idx < total_segments && out.len() < limit {
            // Special final "segment": the currently-appending head segment (if enabled).
            if seg_idx == sealed_len {
                // SAFETY: seg_idx == sealed_len is only reachable when has_head is true.
                #[allow(clippy::expect_used)]
                let head = self.head.as_ref().expect("head exists when seg_idx==sealed_len");
                let record_end = (corecrux_segment::SEGMENT_HEADER_LEN as u64).saturating_add(head.record_len);

                if offset < corecrux_segment::SEGMENT_HEADER_LEN as u64 {
                    offset = corecrux_segment::SEGMENT_HEADER_LEN as u64;
                }
                if offset >= record_end {
                    seg_idx += 1;
                    offset = corecrux_segment::SEGMENT_HEADER_LEN as u64;
                    continue;
                }

                let start_pos = head.frames.partition_point(|f| {
                    let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64).saturating_add(f.record_off as u64);
                    frame_off < offset
                });
                if start_pos >= head.frames.len() {
                    seg_idx += 1;
                    offset = corecrux_segment::SEGMENT_HEADER_LEN as u64;
                    continue;
                }

                let remaining = limit.saturating_sub(out.len());
                let take = remaining.min(head.frames.len() - start_pos);
                let slice = &head.frames[start_pos..start_pos + take];
                let mut block_ids: Vec<u32> = slice.iter().map(|f| f.block_id).collect();
                block_ids.sort_unstable();
                block_ids.dedup();
                let blocks = read_blocks_cpu(&head.file, &head.blocks, &block_ids)?;

                for f in slice {
                    if out.len() >= limit {
                        break;
                    }
                    let bid = f.block_id as usize;
                    let Some(buf) = blocks.get(bid).and_then(|v| v.as_ref()) else {
                        return Err(StorageError::ManifestRecordInvalid {
                            msg: "head block buffer missing".to_string(),
                        });
                    };
                    let start = f.in_block_offset as usize;
                    let len = f.frame_len as usize;
                    let end = start.checked_add(len).ok_or(StorageError::ManifestRecordInvalid {
                        msg: "head replay frame slice overflow".to_string(),
                    })?;
                    if end > buf.len() {
                        return Err(StorageError::ManifestRecordInvalid {
                            msg: "head replay frame points outside uncompressed block".to_string(),
                        });
                    }

                    let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64).saturating_add(f.record_off as u64);
                    let frame = buf[start..end].to_vec();
                    let _ = decode_frame_v1(&frame)?;
                    let loc = FrameLocation {
                        shard_id: self.shard_id as u64,
                        epoch: self.epoch,
                        segment_seq: head.segment_seq,
                        offset: frame_off,
                    };
                    out.push((loc, frame));
                    offset = frame_off.saturating_add(f.frame_len as u64);
                }

                if out.len() >= limit {
                    if offset >= record_end {
                        return Ok((out, None));
                    }
                    return Ok((
                        out,
                        Some(ReplayCursor {
                            segment_seq: head.segment_seq,
                            offset,
                        }),
                    ));
                }

                seg_idx += 1;
                offset = corecrux_segment::SEGMENT_HEADER_LEN as u64;
                continue;
            }

            let seg = &self.segments_in_order[seg_idx];
            let seg_path = self.paths.shard_dir.join(&seg.relative_path);
            let record_end: u64;

            if let Some(ti) = self.segment_trailers_by_seq.get(&seg.segment_seq) {
                let block_starts = block_logical_starts(&ti.blocks)?;
                let total_uncompressed_len = ti
                    .blocks
                    .iter()
                    .try_fold(0u64, |acc, b| acc.checked_add(b.uncompressed_len as u64))
                    .ok_or(StorageError::ManifestRecordInvalid {
                        msg: "block uncompressed_len overflow".to_string(),
                    })?;
                record_end = (corecrux_segment::SEGMENT_HEADER_LEN as u64) + total_uncompressed_len;

                let file = File::open(&seg_path).map_err(io_err)?;
                let start_pos = ti.toc_by_offset.partition_point(|e| {
                    let bid = e.block_id as usize;
                    let Some(block_start) = block_starts.get(bid) else {
                        return true;
                    };
                    let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                        .saturating_add(*block_start)
                        .saturating_add(e.in_block_offset as u64);
                    frame_off < offset
                });

                if start_pos >= ti.toc_by_offset.len() {
                    seg_idx += 1;
                    offset = corecrux_segment::SEGMENT_HEADER_LEN as u64;
                    continue;
                }

                let remaining = limit.saturating_sub(out.len());
                let take = remaining.min(ti.toc_by_offset.len() - start_pos);
                let slice = &ti.toc_by_offset[start_pos..start_pos + take];
                let mut block_ids: Vec<u32> = slice.iter().map(|e| e.block_id).collect();
                block_ids.sort_unstable();
                block_ids.dedup();
                let blocks = read_blocks_cpu(&file, &ti.blocks, &block_ids)?;

                for e in slice {
                    if out.len() >= limit {
                        break;
                    }
                    let bid = e.block_id as usize;
                    let Some(buf) = blocks.get(bid).and_then(|v| v.as_ref()) else {
                        return Err(StorageError::ManifestRecordInvalid {
                            msg: "block buffer missing".to_string(),
                        });
                    };
                    let start = e.in_block_offset as usize;
                    let len = e.frame_len as usize;
                    let end = start.checked_add(len).ok_or(StorageError::ManifestRecordInvalid {
                        msg: "frame slice overflow".to_string(),
                    })?;
                    if end > buf.len() {
                        return Err(StorageError::ManifestRecordInvalid {
                            msg: "replay frame points outside uncompressed block".to_string(),
                        });
                    }

                    let block_start = block_starts
                        .get(bid)
                        .copied()
                        .ok_or(StorageError::ManifestRecordInvalid {
                            msg: "block start missing".to_string(),
                        })?;
                    let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                        .checked_add(block_start)
                        .and_then(|v| v.checked_add(e.in_block_offset as u64))
                        .ok_or(StorageError::ManifestRecordInvalid {
                            msg: "frame offset overflow".to_string(),
                        })?;

                    let frame = buf[start..end].to_vec();
                    let _ = decode_frame_v1(&frame)?;
                    let loc = FrameLocation {
                        shard_id: self.shard_id as u64,
                        epoch: seg.epoch,
                        segment_seq: seg.segment_seq,
                        offset: frame_off,
                    };
                    out.push((loc, frame));
                    offset = frame_off.saturating_add(e.frame_len as u64);
                }
            } else {
                // Fallback: Phase 2 scan.
                let bytes = std::fs::read(&seg_path).map_err(io_err)?;
                let (_h, _toc_h, _entries, footer) = decode_segment_v1(&bytes)?;
                let record_start = footer.record_area_offset;
                record_end = footer.toc_offset;

                if offset < record_start {
                    offset = record_start;
                }

                while offset < record_end && out.len() < limit {
                    let frame_len =
                        frame_len_at(&bytes, offset).ok_or_else(|| StorageError::ManifestRecordInvalid {
                            msg: "failed to compute frame length at replay cursor".to_string(),
                        })?;
                    let end = offset.saturating_add(frame_len as u64);
                    if end > record_end || end as usize > bytes.len() {
                        return Err(StorageError::ManifestRecordInvalid {
                            msg: "replay frame extends past record area".to_string(),
                        });
                    }

                    let frame = bytes[offset as usize..end as usize].to_vec();
                    let _ = decode_frame_v1(&frame)?;
                    let loc = FrameLocation {
                        shard_id: self.shard_id as u64,
                        epoch: seg.epoch,
                        segment_seq: seg.segment_seq,
                        offset,
                    };
                    out.push((loc, frame));
                    offset = end;
                }
            }

            if out.len() >= limit {
                if offset >= record_end {
                    seg_idx += 1;
                    if seg_idx >= total_segments {
                        return Ok((out, None));
                    }
                    if seg_idx == sealed_len {
                        // SAFETY: seg_idx == sealed_len implies head is Some.
                        #[allow(clippy::expect_used)]
                        let head = self.head.as_ref().expect("head exists");
                        return Ok((
                            out,
                            Some(ReplayCursor {
                                segment_seq: head.segment_seq,
                                offset: corecrux_segment::SEGMENT_HEADER_LEN as u64,
                            }),
                        ));
                    }
                    let next_seg = &self.segments_in_order[seg_idx];
                    return Ok((
                        out,
                        Some(ReplayCursor {
                            segment_seq: next_seg.segment_seq,
                            offset: corecrux_segment::SEGMENT_HEADER_LEN as u64,
                        }),
                    ));
                }
                return Ok((
                    out,
                    Some(ReplayCursor {
                        segment_seq: seg.segment_seq,
                        offset,
                    }),
                ));
            }

            seg_idx += 1;
            offset = corecrux_segment::SEGMENT_HEADER_LEN as u64;
        }

        Ok((out, None))
    }

    pub fn read_frame_bytes(&self, segment_seq: u64, offset: u64) -> Result<Vec<u8>> {
        if let Some(head) = self.head.as_ref() {
            if head.segment_seq == segment_seq {
                let (block_idx, in_block_offset) = logical_offset_to_block(&head.blocks, offset)?;
                let blocks = read_blocks_cpu(&head.file, &head.blocks, &[block_idx as u32])?;
                let Some(buf) = blocks.get(block_idx).and_then(|v| v.as_ref()) else {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: "head block buffer missing".to_string(),
                    });
                };
                let frame_len = frame_len_at(buf, in_block_offset as u64).ok_or(StorageError::Io {
                    msg: "failed to compute head frame length for logical offset".to_string(),
                })?;
                let start = in_block_offset as usize;
                let end = start.saturating_add(frame_len);
                if end > buf.len() {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: "head frame points outside uncompressed block".to_string(),
                    });
                }
                return Ok(buf[start..end].to_vec());
            }
        }

        let seg = self
            .segments_by_seq
            .get(&segment_seq)
            .ok_or_else(|| StorageError::ManifestRecordInvalid {
                msg: format!("segment_seq {segment_seq} not found"),
            })?;
        let seg_path = self.paths.shard_dir.join(&seg.relative_path);
        if let Some(ti) = self.segment_trailers_by_seq.get(&segment_seq) {
            let file = File::open(&seg_path).map_err(io_err)?;
            let (block_idx, in_block_offset) = logical_offset_to_block(&ti.blocks, offset)?;
            let blocks = read_blocks_cpu(&file, &ti.blocks, &[block_idx as u32])?;
            let Some(buf) = blocks.get(block_idx).and_then(|v| v.as_ref()) else {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: "block buffer missing".to_string(),
                });
            };
            let frame_len = frame_len_at(buf, in_block_offset as u64).ok_or(StorageError::Io {
                msg: "failed to compute frame length for logical offset".to_string(),
            })?;
            let start = in_block_offset as usize;
            let end = start.saturating_add(frame_len);
            if end > buf.len() {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: "frame points outside uncompressed block".to_string(),
                });
            }
            return Ok(buf[start..end].to_vec());
        }

        read_frame_bytes_physical(&seg_path, offset)
    }

    pub fn read_frame_bytes_batch(&self, locations: &[FrameLocation]) -> Result<Vec<Vec<u8>>> {
        let packed = self.read_frame_bytes_batch_packed(locations)?;
        let mut out = Vec::with_capacity(packed.frame_lens.len());
        for (off, len) in packed
            .frame_offsets
            .iter()
            .copied()
            .zip(packed.frame_lens.iter().copied())
        {
            let start = off as usize;
            let end = start.saturating_add(len as usize);
            if end > packed.frames_blob.len() {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: "packed frame range exceeds blob bounds".to_string(),
                });
            }
            out.push(packed.frames_blob[start..end].to_vec());
        }
        Ok(out)
    }

    pub fn read_frame_bytes_batch_packed(&self, locations: &[FrameLocation]) -> Result<ReadFrameBatchPackedV1> {
        fn extract_frame(buf: &[u8], in_block_offset: usize, context: &str) -> Result<Vec<u8>> {
            let frame_len = frame_len_at(buf, in_block_offset as u64).ok_or(StorageError::Io {
                msg: format!("failed to compute {context} frame length for logical offset"),
            })?;
            let start = in_block_offset;
            let end = start.saturating_add(frame_len);
            if end > buf.len() {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: format!("{context} frame points outside uncompressed block"),
                });
            }
            Ok(buf[start..end].to_vec())
        }

        if locations.is_empty() {
            return Ok(ReadFrameBatchPackedV1 {
                frames_blob: Vec::new(),
                frame_offsets: Vec::new(),
                frame_lens: Vec::new(),
                frame_bytes: 0,
            });
        }

        let mut frames_blob = Vec::new();
        let mut frame_offsets = Vec::with_capacity(locations.len());
        let mut frame_lens = Vec::with_capacity(locations.len());
        let mut frame_bytes = 0u64;
        let mut cached_head_block: Option<(u32, Vec<u8>)> = None;
        let mut cached_sealed_block: Option<(u64, u32, Vec<u8>)> = None;
        let mut cached_sealed_file: Option<(u64, File)> = None;

        for loc in locations {
            let push_frame = |frame: &[u8],
                              frames_blob: &mut Vec<u8>,
                              frame_offsets: &mut Vec<u32>,
                              frame_lens: &mut Vec<u32>,
                              frame_bytes: &mut u64|
             -> Result<()> {
                let off = u32::try_from(frames_blob.len()).map_err(|_| StorageError::Io {
                    msg: "packed frame offset overflow".to_string(),
                })?;
                let len = u32::try_from(frame.len()).map_err(|_| StorageError::Io {
                    msg: "packed frame length overflow".to_string(),
                })?;
                frame_offsets.push(off);
                frame_lens.push(len);
                *frame_bytes = frame_bytes.saturating_add(frame.len() as u64);
                frames_blob.extend_from_slice(frame);
                Ok(())
            };

            if let Some(head) = self.head.as_ref() {
                if head.segment_seq == loc.segment_seq {
                    let (block_idx, in_block_offset) = logical_offset_to_block(&head.blocks, loc.offset)?;
                    let needs_reload = cached_head_block
                        .as_ref()
                        .is_none_or(|(cached_idx, _)| *cached_idx != block_idx as u32);
                    if needs_reload {
                        let blocks = read_blocks_cpu(&head.file, &head.blocks, &[block_idx as u32])?;
                        let Some(buf) = blocks.get(block_idx).and_then(|v| v.as_ref()) else {
                            return Err(StorageError::ManifestRecordInvalid {
                                msg: "head block buffer missing".to_string(),
                            });
                        };
                        cached_head_block = Some((block_idx as u32, buf.clone()));
                    }
                    // SAFETY: cached_head_block is set to Some in the reload block above.
                    #[allow(clippy::expect_used)]
                    let cached_head_ref = &cached_head_block.as_ref().expect("cached head block just loaded").1;
                    let frame = extract_frame(cached_head_ref, in_block_offset as usize, "head")?;
                    push_frame(
                        &frame,
                        &mut frames_blob,
                        &mut frame_offsets,
                        &mut frame_lens,
                        &mut frame_bytes,
                    )?;
                    continue;
                }
            }

            let seg =
                self.segments_by_seq
                    .get(&loc.segment_seq)
                    .ok_or_else(|| StorageError::ManifestRecordInvalid {
                        msg: format!("segment_seq {} not found", loc.segment_seq),
                    })?;
            let seg_path = self.paths.shard_dir.join(&seg.relative_path);
            if let Some(ti) = self.segment_trailers_by_seq.get(&loc.segment_seq) {
                let (block_idx, in_block_offset) = logical_offset_to_block(&ti.blocks, loc.offset)?;
                let block_idx_u32 = block_idx as u32;
                let needs_reload = !cached_sealed_block
                    .as_ref()
                    .is_some_and(|(cached_seg, cached_block, _)| {
                        *cached_seg == loc.segment_seq && *cached_block == block_idx_u32
                    });
                if needs_reload {
                    let file_seq = cached_sealed_file.as_ref().map(|(seq, _)| *seq);
                    if file_seq != Some(loc.segment_seq) {
                        let file = File::open(&seg_path).map_err(io_err)?;
                        cached_sealed_file = Some((loc.segment_seq, file));
                    }
                    // SAFETY: cached_sealed_file is set to Some in the block above.
                    #[allow(clippy::expect_used)]
                    let file_ref = &cached_sealed_file.as_ref().expect("cached sealed file just loaded").1;
                    let blocks = read_blocks_cpu(file_ref, &ti.blocks, &[block_idx_u32])?;
                    let Some(buf) = blocks.get(block_idx).and_then(|v| v.as_ref()) else {
                        return Err(StorageError::ManifestRecordInvalid {
                            msg: "block buffer missing".to_string(),
                        });
                    };
                    cached_sealed_block = Some((loc.segment_seq, block_idx_u32, buf.clone()));
                }
                // SAFETY: cached_sealed_block is set to Some in the reload block above.
                #[allow(clippy::expect_used)]
                let cached_block_ref = &cached_sealed_block.as_ref().expect("cached sealed block just loaded").2;
                let frame = extract_frame(cached_block_ref, in_block_offset as usize, "sealed")?;
                push_frame(
                    &frame,
                    &mut frames_blob,
                    &mut frame_offsets,
                    &mut frame_lens,
                    &mut frame_bytes,
                )?;
            } else {
                let frame = read_frame_bytes_physical(&seg_path, loc.offset)?;
                push_frame(
                    &frame,
                    &mut frames_blob,
                    &mut frame_offsets,
                    &mut frame_lens,
                    &mut frame_bytes,
                )?;
            }
        }

        Ok(ReadFrameBatchPackedV1 {
            frames_blob,
            frame_offsets,
            frame_lens,
            frame_bytes,
        })
    }
}
