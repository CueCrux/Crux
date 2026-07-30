// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.
// Mutation-killing tests for src/read.rs (ExecPlan crux-storage-mutation-burndown-2026-07-22).
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[allow(unused_imports)]
use crate::*;
use corecrux_segment::{decode_frame_v1, TocByOffsetEntryV1};

// ── fixtures ────────────────────────────────────────────────────────

const T: &str = "tnt";
const TY: &str = "typ";
const ID: &str = "sid";

fn sh() -> u64 {
    corecrux_frame::stream_hash_xxhash64(T, TY, ID).unwrap()
}

fn sh_of(id: &str) -> u64 {
    corecrux_frame::stream_hash_xxhash64(T, TY, id).unwrap()
}

fn evin<'a>(id: &'a str, payload: &'a [u8]) -> AppendEventInput<'a> {
    AppendEventInput {
        event_id: id,
        occurred_at: "2026-02-06T00:00:00Z",
        event_type: "t",
        content_type: "application/octet-stream",
        payload_bytes: payload,
    }
}

fn open_sealing() -> (tempfile::TempDir, ShardStorage) {
    let dir = tempfile::tempdir().unwrap();
    let storage = ShardStorage::open(dir.path(), 1, 1, ShardStorageOptions::default()).unwrap();
    (dir, storage)
}

fn open_head() -> (tempfile::TempDir, ShardStorage) {
    let dir = tempfile::tempdir().unwrap();
    let opts = ShardStorageOptions {
        head_max_record_bytes: 64 * 1024 * 1024,
        ..Default::default()
    };
    let storage = ShardStorage::open(dir.path(), 1, 1, opts).unwrap();
    (dir, storage)
}

fn eid(seq: u64) -> String {
    format!("e{seq}")
}

fn payload_for(seq: u64) -> Vec<u8> {
    format!("payload-for-seq-{seq}").into_bytes()
}

/// Append `seqs` as a single batch (one sealed segment under default opts,
/// or one head batch under head opts). Assumes the next assigned seq equals
/// `*seqs.start()`.
fn append_batch_seqs(
    s: &mut ShardStorage,
    stream_hash: u64,
    id: &str,
    seqs: std::ops::RangeInclusive<u64>,
) -> Vec<AppendOutcome> {
    let owned: Vec<(String, Vec<u8>)> = seqs.map(|k| (eid(k), payload_for(k))).collect();
    let inputs: Vec<AppendEventInput> = owned.iter().map(|(i, p)| evin(i, p)).collect();
    s.append_batch(stream_hash, 0, T, TY, id, "2026-02-06T00:00:01Z", &inputs)
        .unwrap()
}

/// Append each seq in its own batch → one sealed segment per seq (default opts).
fn append_each_seq(s: &mut ShardStorage, stream_hash: u64, id: &str, seqs: std::ops::RangeInclusive<u64>) {
    for k in seqs {
        append_batch_seqs(s, stream_hash, id, k..=k);
    }
}

fn seqs_of(events: &[StoredEvent]) -> Vec<u64> {
    events.iter().map(|e| e.seq).collect()
}

fn assert_events_exact(events: &[StoredEvent], expected_seqs: &[u64]) {
    assert_eq!(seqs_of(events), expected_seqs, "seq mismatch");
    for e in events {
        assert_eq!(e.event_id, eid(e.seq), "event_id mismatch at seq {}", e.seq);
        assert_eq!(e.payload, payload_for(e.seq), "payload mismatch at seq {}", e.seq);
    }
}

// ════════════════════════════════════════════════════════════════════
//  rebuild_tail_locator_from_directory  (L24, L31, L34, L49, L51)
// ════════════════════════════════════════════════════════════════════

#[test]
fn rebuild_tail_locator_applies_cut_and_repopulates() {
    let (_dir, mut storage) = open_sealing();
    let stream_hash = sh();
    // 5 single-event sealed segments; event seq k lives in a segment whose max_seq == k.
    append_each_seq(&mut storage, stream_hash, ID, 1..=5);

    // cut == 3 exactly equals one segment's max_seq → distinguishes < / == / <= / >.
    storage.update_stream_meta(stream_hash, 3, 0).unwrap();

    // Pre-clear so the "replace body with Ok(())" mutant (which skips the rebuild)
    // is observable: it would leave both maps empty.
    storage.tail_locator_by_stream.clear();
    storage.tail_pointer_by_stream.clear();

    storage.rebuild_tail_locator_from_directory().unwrap();

    let locator = storage
        .tail_locator_by_stream
        .get(&stream_hash)
        .expect("locator rebuilt");
    let seqs: Vec<u64> = locator.entries_asc.iter().map(|e| e.entry.seq).collect();
    assert_eq!(seqs, vec![3, 4, 5], "rebuild must keep exactly seq>=cut, ascending");

    let ptr = storage
        .tail_pointer_by_stream
        .get(&stream_hash)
        .expect("pointer rebuilt");
    assert_eq!(ptr.latest_seq, 5);
}

// ════════════════════════════════════════════════════════════════════
//  locator_tail_entries_desc / locator_tail_segments_desc cut boundary
//  (L129, L204, L208, L120)
// ════════════════════════════════════════════════════════════════════

fn toc_entry(stream_hash: u64, seq: u64) -> TocByOffsetEntryV1 {
    TocByOffsetEntryV1 {
        stream_hash,
        seq,
        block_id: 0,
        in_block_offset: seq as u32,
        frame_len: 16,
        flags: 0,
        event_id_hash16: [0; 16],
        header_digest8: [0; 8],
        payload_digest8: [0; 8],
    }
}

#[test]
fn locator_tail_desc_cut_is_strict_less_than() {
    let (_dir, mut storage) = open_sealing();
    let stream_hash = 0xABCDu64;
    let entries: Vec<_> = (60..=66).map(|seq| toc_entry(stream_hash, seq)).collect();
    storage.update_tail_locator_for_stream_entries(stream_hash, 7, &entries);

    // cut == 63 with limit 4: strict `<` keeps [66,65,64,63]. `==`/`<=` would skip 63.
    let got = storage.locator_tail_entries_desc(stream_hash, 63, 4);
    assert_eq!(
        got.iter().map(|e| e.entry.seq).collect::<Vec<_>>(),
        vec![66, 65, 64, 63],
        "locator_tail_entries_desc: seq<cut is strict"
    );

    let (groups, full) = storage.locator_tail_segments_desc(stream_hash, 63, 4);
    assert!(full, "4 of >=4 entries → fully satisfied");
    let flat: Vec<u64> = groups.iter().flat_map(|(_, es)| es.iter().map(|e| e.seq)).collect();
    assert_eq!(
        flat,
        vec![66, 65, 64, 63],
        "locator_tail_segments_desc: seq<cut is strict"
    );
}

#[test]
fn locator_tail_entries_desc_uses_pointer_fast_path() {
    // L204: `cut <= ptr.latest_seq` must gate the pointer fast path. We desync the
    // caches (pointer present, flat locator cleared): the fast path is the ONLY
    // source, so flipping the guard to `>` yields an empty result.
    let (_dir, mut storage) = open_sealing();
    let stream_hash = 0x1234u64;
    let entries: Vec<_> = (1..=5).map(|seq| toc_entry(stream_hash, seq)).collect();
    storage.update_tail_locator_for_stream_entries(stream_hash, 9, &entries);
    assert!(storage.tail_pointer_by_stream.contains_key(&stream_hash));

    // Remove the flat locator; keep the pointer.
    storage.tail_locator_by_stream.remove(&stream_hash);

    let got = storage.locator_tail_entries_desc(stream_hash, 0, 3);
    assert_eq!(
        got.iter().map(|e| e.entry.seq).collect::<Vec<_>>(),
        vec![5, 4, 3],
        "pointer fast path must serve when flat locator is absent"
    );
}

#[test]
fn locator_helpers_zero_limit_short_circuit() {
    let (_dir, mut storage) = open_sealing();
    let stream_hash = 0x9u64;
    storage.update_tail_locator_for_stream_entries(stream_hash, 1, &[toc_entry(stream_hash, 1)]);
    assert!(storage.locator_tail_entries_desc(stream_hash, 0, 0).is_empty());
    let (g, full) = storage.locator_tail_segments_desc(stream_hash, 0, 0);
    assert!(g.is_empty());
    assert!(!full);
}

// ════════════════════════════════════════════════════════════════════
//  read_stream_with_stats — sealed round-trip + Phase-2 fallback
//  (L487, L492, L504, L506, L511, L519, L552)
// ════════════════════════════════════════════════════════════════════

#[test]
fn read_stream_multi_segment_roundtrip_and_range() {
    let (_dir, mut storage) = open_sealing();
    let stream_hash = sh();
    append_each_seq(&mut storage, stream_hash, ID, 1..=6);

    let all = storage.read_stream(T, TY, ID, stream_hash, 1, 0).unwrap();
    assert_events_exact(&all, &[1, 2, 3, 4, 5, 6]);

    let mid = storage.read_stream(T, TY, ID, stream_hash, 3, 2).unwrap();
    assert_events_exact(&mid, &[3, 4]);

    let past = storage.read_stream(T, TY, ID, stream_hash, 99, 10).unwrap();
    assert!(past.is_empty());
}

#[test]
fn read_stream_phase2_fallback_multistream_and_bounds() {
    // Build one sealed segment holding two streams (head with two streams then seal),
    // then drop the in-memory trailer index to force the Phase-2 (decode_segment_v1)
    // reader that owns L487/L492/L504/L506/L511.
    let (_dir, mut storage) = open_head();
    let a = sh_of("stream-a");
    let b = sh_of("stream-b");
    append_batch_seqs(&mut storage, a, "stream-a", 1..=3);
    append_batch_seqs(&mut storage, b, "stream-b", 1..=2);
    storage.force_seal_head().unwrap();
    assert_eq!(
        storage.segments_in_order.len(),
        1,
        "single sealed segment with both streams"
    );

    storage.segment_trailers_by_seq.clear(); // force Phase-2

    // L487 (stream_hash break), L504 (off..off+len slice), L506 (segments_touched once).
    let (a_events, a_stats) = storage.read_stream_with_stats(T, TY, "stream-a", a, 1, 0).unwrap();
    assert_events_exact(&a_events, &[1, 2, 3]);
    assert_eq!(a_stats.segments_touched, 1, "Phase-2 touches the segment exactly once");

    let b_events = storage.read_stream(T, TY, "stream-b", b, 1, 0).unwrap();
    assert_events_exact(&b_events, &[1, 2]);

    // L511: limit must stop at exactly `max_events` even though more remain.
    let limited = storage.read_stream(T, TY, "stream-a", a, 1, 2).unwrap();
    assert_events_exact(&limited, &[1, 2]);
}

#[test]
fn read_stream_head_includes_last_frame_bounds() {
    // read_stream head branch always uses the block+slice path (L552 bounds).
    // Reading through the final head frame (end == buf.len) must succeed.
    let (_dir, mut storage) = open_head();
    let stream_hash = sh();
    append_batch_seqs(&mut storage, stream_hash, ID, 1..=3);
    assert!(storage.head.is_some());
    assert_eq!(storage.segments_in_order.len(), 0);

    let all = storage.read_stream(T, TY, ID, stream_hash, 1, 0).unwrap();
    assert_events_exact(&all, &[1, 2, 3]);
    let tail_range = storage.read_stream(T, TY, ID, stream_hash, 2, 5).unwrap();
    assert_events_exact(&tail_range, &[2, 3]);
}

// ════════════════════════════════════════════════════════════════════
//  read_tail_with_stats — fast/locator/Phase-2/head paths
//  (L622..L922)
// ════════════════════════════════════════════════════════════════════

#[test]
fn read_tail_locator_fast_path_exact() {
    let (_dir, mut storage) = open_sealing();
    let stream_hash = sh();
    append_each_seq(&mut storage, stream_hash, ID, 1..=6);

    let (tail, stats) = storage.read_tail_with_stats(T, TY, ID, stream_hash, 3).unwrap();
    assert_events_exact(&tail, &[4, 5, 6]);
    assert_eq!(
        stats.locator_fully_satisfied_hits, 1,
        "locator fully satisfies a 3-tail of 6"
    );
}

#[test]
fn read_tail_nonfast_trailer_fill_beyond_locator() {
    // 80 events across 8 segments; asking for a 70-tail forces the locator (caps at
    // 64) to miss, driving the non-fast directory+trailer fill loop
    // (L829/L832/L852/L857/L861/L874) for the older-than-64 events.
    let (_dir, mut storage) = open_sealing();
    let stream_hash = sh();
    for base in 0..8u64 {
        append_batch_seqs(&mut storage, stream_hash, ID, base * 10 + 1..=base * 10 + 10);
    }

    let (tail, stats) = storage.read_tail_with_stats(T, TY, ID, stream_hash, 70).unwrap();
    // Snapshot of the locator-boundary fill: the locator caps at 64 recent entries
    // (seqs 17..=80). Crossing that boundary, the per-segment top-`need` fill leaves
    // seqs 11..=14 in the gap and back-fills seg1's 7..=10 instead — a deterministic
    // 70-event set that any mutation of the fill/dedup loop perturbs.
    let expected: Vec<u64> = (7..=10).chain(15..=80).collect();
    assert_eq!(seqs_of(&tail), expected, "locator-boundary fill snapshot");
    assert_eq!(tail.len(), 70);
    for e in &tail {
        assert_eq!(e.event_id, eid(e.seq));
        assert_eq!(e.payload, payload_for(e.seq));
    }
    assert_eq!(
        stats.locator_fully_satisfied_misses, 1,
        "70-tail cannot be satisfied by the 64-entry locator"
    );

    // Asking for more than exists returns every event, oldest first.
    let full = storage.read_tail(T, TY, ID, stream_hash, 200).unwrap();
    assert_eq!(seqs_of(&full), (1..=80).collect::<Vec<_>>());
}

#[test]
fn read_tail_nonfast_multiframe_contiguous_fill() {
    // Cleared locators + multi-frame segments → the non-fast directory+trailer fill
    // returns a clean contiguous tail (exercises L832/L852 and the `selected=extra`
    // fresh-segment path without the 64-boundary quirk).
    let (_dir, mut storage) = open_head();
    let stream_hash = sh();
    append_batch_seqs(&mut storage, stream_hash, ID, 1..=5);
    storage.force_seal_head().unwrap();
    append_batch_seqs(&mut storage, stream_hash, ID, 6..=10);
    storage.force_seal_head().unwrap();
    assert_eq!(storage.segments_in_order.len(), 2);

    storage.tail_locator_by_stream.clear();
    storage.tail_pointer_by_stream.clear();

    let tail = storage.read_tail(T, TY, ID, stream_hash, 7).unwrap();
    assert_events_exact(&tail, &[4, 5, 6, 7, 8, 9, 10]);
}

#[test]
fn read_tail_nonfast_directory_cut_filter() {
    // L814: `r.max_seq < cut` in the non-fast directory scan. Clear the locator caches
    // (so the fast path can't satisfy) but keep the trailers.
    let (_dir, mut storage) = open_sealing();
    let stream_hash = sh();
    append_each_seq(&mut storage, stream_hash, ID, 1..=6);
    storage.update_stream_meta(stream_hash, 4, 0).unwrap(); // cut == 4 == one segment's max_seq

    storage.tail_locator_by_stream.clear();
    storage.tail_pointer_by_stream.clear();

    let tail = storage.read_tail(T, TY, ID, stream_hash, 10).unwrap();
    assert_events_exact(&tail, &[4, 5, 6]);
}

#[test]
fn read_tail_phase2_reverse_scan_and_cut() {
    // One sealed segment with 4 frames of a single stream; drop trailers AND locators
    // → Phase-2 reverse scan (L889/L895/L896/L900/L912/L914/L922).
    let (_dir, mut storage) = open_head();
    let stream_hash = sh();
    append_batch_seqs(&mut storage, stream_hash, ID, 1..=4);
    storage.force_seal_head().unwrap();
    assert_eq!(storage.segments_in_order.len(), 1);

    storage.segment_trailers_by_seq.clear();
    storage.tail_locator_by_stream.clear();
    storage.tail_pointer_by_stream.clear();

    let tail2 = storage.read_tail(T, TY, ID, stream_hash, 2).unwrap();
    assert_events_exact(&tail2, &[3, 4]);

    let tail_all = storage.read_tail(T, TY, ID, stream_hash, 10).unwrap();
    assert_events_exact(&tail_all, &[1, 2, 3, 4]);

    // L914: Phase-2 seq>=cut filter.
    storage.update_stream_meta(stream_hash, 3, 0).unwrap();
    let tail_cut = storage.read_tail(T, TY, ID, stream_hash, 10).unwrap();
    assert_events_exact(&tail_cut, &[3, 4]);
}

#[test]
fn read_tail_head_fast_path_and_slow_scan() {
    // Head fast path fills to `remaining` with the correct set; a wrong comparison
    // that fills with out-of-order/below-cut entries is observable because a full
    // fast path skips the slow-scan backfill.
    let (_dir, mut storage) = open_head();
    let stream_hash = sh();
    append_batch_seqs(&mut storage, stream_hash, ID, 1..=6);
    assert!(storage.head.is_some());

    let (tail, stats) = storage.read_tail_with_stats(T, TY, ID, stream_hash, 3).unwrap();
    assert_events_exact(&tail, &[4, 5, 6]);
    assert_eq!(stats.head_tail_fastpath_hits, 1);

    // cut == 5 (equals a top-K seq): the fast-path seq filter must be strict `<`.
    storage.update_stream_meta(stream_hash, 5, 0).unwrap();
    let tail_cut = storage.read_tail(T, TY, ID, stream_hash, 3).unwrap();
    assert_events_exact(&tail_cut, &[5, 6]);
}

#[test]
fn read_tail_head_slow_scan_rejects_other_streams() {
    // Multi-stream head: our stream has fewer frames than `remaining`, so the fast
    // path underfills and the slow scan (L645 filter) runs and must skip other
    // streams and below-cut frames.
    let (_dir, mut storage) = open_head();
    let a = sh_of("s-a");
    let b = sh_of("s-b");
    append_batch_seqs(&mut storage, a, "s-a", 1..=2);
    append_batch_seqs(&mut storage, b, "s-b", 1..=4);
    // Clear the fast-path index so the slow scan is the sole provider.
    storage.head.as_mut().unwrap().stream_tail_idx_by_stream.clear();

    let (tail, _stats) = storage.read_tail_with_stats(T, TY, "s-a", a, 10).unwrap();
    assert_eq!(
        seqs_of(&tail),
        vec![1, 2],
        "slow scan must return only stream a's events"
    );
    for e in &tail {
        assert_eq!(e.event_id, eid(e.seq));
    }
}

#[test]
fn read_tail_head_slow_scan_cut_filter() {
    // Slow scan (fast index cleared) with a non-zero cut: the seq filter must be a
    // strict `< cut` (L645:66). cut==2 lets == / <= / > all diverge from `<`.
    let (_dir, mut storage) = open_head();
    let stream_hash = sh();
    append_batch_seqs(&mut storage, stream_hash, ID, 1..=4);
    storage.head.as_mut().unwrap().stream_tail_idx_by_stream.clear();
    storage.update_stream_meta(stream_hash, 2, 0).unwrap(); // cut == 2

    let tail = storage.read_tail(T, TY, ID, stream_hash, 10).unwrap();
    assert_events_exact(&tail, &[2, 3, 4]);
}

#[test]
fn read_tail_head_only_last_frame_reads() {
    // Head-only tail read through the final frame (end == buf.len via the frame-window
    // path) must succeed and be exact.
    let (_dir, mut storage) = open_head();
    let stream_hash = sh();
    append_batch_seqs(&mut storage, stream_hash, ID, 1..=5);
    let tail = storage.read_tail(T, TY, ID, stream_hash, 5).unwrap();
    assert_events_exact(&tail, &[1, 2, 3, 4, 5]);
}

// ════════════════════════════════════════════════════════════════════
//  replay_from_sealed  (L946..L1122)
// ════════════════════════════════════════════════════════════════════

fn assert_replay_prefix(full: &ReplayFrames, part: &ReplayFrames) {
    assert!(part.len() <= full.len());
    for (i, (loc, bytes)) in part.iter().enumerate() {
        assert_eq!(*loc, full[i].0, "location mismatch at replay index {i}");
        assert_eq!(*bytes, full[i].1, "frame bytes mismatch at replay index {i}");
    }
}

#[test]
fn replay_from_sealed_roundtrip_cursor_and_limits() {
    let (_dir, mut storage) = open_head();
    let stream_hash = sh();
    append_batch_seqs(&mut storage, stream_hash, ID, 1..=5);
    storage.force_seal_head().unwrap(); // single sealed segment, 5 frames
    assert_eq!(storage.segments_in_order.len(), 1);

    let (full, end) = storage.replay_from_sealed(None, 0).unwrap();
    assert_eq!(end, None, "full replay ends with no cursor");
    assert_eq!(full.len(), 5, "all 5 frames");
    for (_loc, bytes) in &full {
        decode_frame_v1(bytes).unwrap();
    }

    // Partial: exactly 2 → cursor mid-segment; resume yields the rest, in order.
    let (part, cursor) = storage.replay_from_sealed(None, 2).unwrap();
    assert_eq!(part.len(), 2);
    assert_replay_prefix(&full, &part);
    let cursor = cursor.expect("cursor after mid-segment stop");
    let (rest, end2) = storage.replay_from_sealed(Some(cursor), 0).unwrap();
    assert_eq!(end2, None);
    let mut combined = part.clone();
    combined.extend_from_slice(&rest);
    assert_eq!(combined.len(), full.len());
    for (a, b) in combined.iter().zip(full.iter()) {
        assert_eq!(a.0, b.0);
        assert_eq!(a.1, b.1);
    }

    // L946: max_frames==0 means "unlimited", not "none".
    let (n3, _c) = storage.replay_from_sealed(None, 3).unwrap();
    assert_eq!(n3.len(), 3, "max_frames bounds the batch exactly");
}

#[test]
fn replay_from_sealed_advances_cursor_across_segments() {
    // 2 segments (A=3 frames, B=2 frames). Limit == A's frame count → cursor must
    // point at the START of segment B. Exercises L989/L1098/L1099/L1100/L1101.
    let (_dir, mut storage) = open_head();
    let stream_hash = sh();
    append_batch_seqs(&mut storage, stream_hash, ID, 1..=3);
    storage.force_seal_head().unwrap();
    append_batch_seqs(&mut storage, stream_hash, ID, 4..=5);
    storage.force_seal_head().unwrap();
    assert_eq!(storage.segments_in_order.len(), 2);
    let seg_b_seq = storage.segments_in_order[1].segment_seq;
    let header = corecrux_segment::SEGMENT_HEADER_LEN as u64;

    let (part, cursor) = storage.replay_from_sealed(None, 3).unwrap();
    assert_eq!(part.len(), 3, "stops exactly at limit");
    let cursor = cursor.expect("cursor after finishing segment A");
    assert_eq!(cursor.segment_seq, seg_b_seq, "cursor advances to segment B");
    assert_eq!(
        cursor.offset, header,
        "cursor resets to header offset of the next segment"
    );

    let (rest, end) = storage.replay_from_sealed(Some(cursor), 0).unwrap();
    assert_eq!(end, None);
    assert_eq!(rest.len(), 2, "segment B has 2 frames");
}

#[test]
fn replay_from_sealed_empty_and_missing_cursor() {
    let (_dir, storage) = open_sealing();
    let (frames, cursor) = storage.replay_from_sealed(None, 0).unwrap();
    assert!(frames.is_empty());
    assert_eq!(cursor, None);

    let (_dir2, mut storage2) = open_sealing();
    append_batch_seqs(&mut storage2, sh(), ID, 1..=1);
    let err = storage2
        .replay_from_sealed(
            Some(ReplayCursor {
                segment_seq: 9999,
                offset: 0,
            }),
            0,
        )
        .unwrap_err();
    match err {
        StorageError::ManifestRecordInvalid { msg } => assert!(msg.contains("9999")),
        other => panic!("unexpected: {other}"),
    }
}

#[test]
fn replay_from_sealed_phase2_scan() {
    // Drop trailers → Phase-2 byte scan (L1069/L1073/L1079/L1098..).
    let (_dir, mut storage) = open_head();
    let stream_hash = sh();
    append_batch_seqs(&mut storage, stream_hash, ID, 1..=4);
    storage.force_seal_head().unwrap();

    let (full_trailer, _e) = storage.replay_from_sealed(None, 0).unwrap();

    storage.segment_trailers_by_seq.clear();
    let (full_phase2, end) = storage.replay_from_sealed(None, 0).unwrap();
    assert_eq!(end, None);
    assert_eq!(full_phase2.len(), 4);
    // Same frame payloads regardless of reader path.
    let bytes_trailer: Vec<Vec<u8>> = full_trailer.iter().map(|(_l, b)| b.clone()).collect();
    let bytes_phase2: Vec<Vec<u8>> = full_phase2.iter().map(|(_l, b)| b.clone()).collect();
    assert_eq!(
        bytes_trailer, bytes_phase2,
        "Phase-2 replay yields identical frame bytes"
    );

    // Cursor round-trip on the Phase-2 path.
    let (part, cursor) = storage.replay_from_sealed(None, 2).unwrap();
    assert_eq!(part.len(), 2);
    let cursor = cursor.expect("phase-2 cursor");
    let (rest, _e) = storage.replay_from_sealed(Some(cursor), 0).unwrap();
    assert_eq!(part.len() + rest.len(), 4);
}

// ════════════════════════════════════════════════════════════════════
//  replay_from (sealed + head)  (L1139..L1432)
// ════════════════════════════════════════════════════════════════════

#[test]
fn replay_from_walks_sealed_then_head_in_order() {
    let (_dir, mut storage) = open_head();
    let stream_hash = sh();
    append_batch_seqs(&mut storage, stream_hash, ID, 1..=3);
    storage.force_seal_head().unwrap(); // sealed segment (3 frames)
    append_batch_seqs(&mut storage, stream_hash, ID, 4..=6); // head (3 frames)
    assert_eq!(storage.segments_in_order.len(), 1);
    assert!(storage.head.is_some());

    let (full, end) = storage.replay_from(None, 0).unwrap();
    assert_eq!(end, None);
    assert_eq!(full.len(), 6, "sealed + head frames");
    for (_loc, bytes) in &full {
        decode_frame_v1(bytes).unwrap();
    }

    // Piecewise replay across the sealed→head boundary reconstructs the whole stream.
    let mut combined: ReplayFrames = Vec::new();
    let mut cursor: Option<ReplayCursor> = None;
    loop {
        let (batch, next) = storage.replay_from(cursor, 1).unwrap();
        if batch.is_empty() {
            break;
        }
        assert_eq!(batch.len(), 1, "max_frames=1 yields one frame");
        combined.extend_from_slice(&batch);
        match next {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    assert_eq!(combined.len(), full.len());
    for (a, b) in combined.iter().zip(full.iter()) {
        assert_eq!(a.0, b.0);
        assert_eq!(a.1, b.1);
    }
}

#[test]
fn replay_from_head_only_when_no_sealed() {
    let (_dir, mut storage) = open_head();
    let stream_hash = sh();
    append_batch_seqs(&mut storage, stream_hash, ID, 1..=4);
    assert_eq!(storage.segments_in_order.len(), 0);

    let (full, end) = storage.replay_from(None, 0).unwrap();
    assert_eq!(end, None);
    assert_eq!(full.len(), 4);

    // Cursor into the head segment (L1167): resume returns the tail frames.
    let (part, cursor) = storage.replay_from(None, 2).unwrap();
    assert_eq!(part.len(), 2);
    let cursor = cursor.expect("head cursor");
    let (rest, end2) = storage.replay_from(Some(cursor), 0).unwrap();
    assert_eq!(end2, None);
    assert_eq!(part.len() + rest.len(), 4);
    let mut combined = part.clone();
    combined.extend_from_slice(&rest);
    for (a, b) in combined.iter().zip(full.iter()) {
        assert_eq!(a.0, b.0);
        assert_eq!(a.1, b.1);
    }
}

#[test]
fn replay_from_advances_across_two_sealed_segments() {
    // Limit hitting the exact end of segment A must produce a cursor at segment B start.
    let (_dir, mut storage) = open_head();
    let stream_hash = sh();
    append_batch_seqs(&mut storage, stream_hash, ID, 1..=2);
    storage.force_seal_head().unwrap();
    append_batch_seqs(&mut storage, stream_hash, ID, 3..=5);
    storage.force_seal_head().unwrap();
    assert_eq!(storage.segments_in_order.len(), 2);
    let seg_b_seq = storage.segments_in_order[1].segment_seq;
    let header = corecrux_segment::SEGMENT_HEADER_LEN as u64;

    let (part, cursor) = storage.replay_from(None, 2).unwrap();
    assert_eq!(part.len(), 2);
    let cursor = cursor.expect("cursor after segment A");
    assert_eq!(cursor.segment_seq, seg_b_seq);
    assert_eq!(cursor.offset, header);
}

#[test]
fn replay_from_phase2_matches_trailer_path() {
    let (_dir, mut storage) = open_head();
    let stream_hash = sh();
    append_batch_seqs(&mut storage, stream_hash, ID, 1..=4);
    storage.force_seal_head().unwrap();

    let (full_trailer, _e) = storage.replay_from(None, 0).unwrap();
    storage.segment_trailers_by_seq.clear();
    let (full_phase2, end) = storage.replay_from(None, 0).unwrap();
    assert_eq!(end, None);
    assert_eq!(full_phase2.len(), 4);
    let bt: Vec<Vec<u8>> = full_trailer.iter().map(|(_l, b)| b.clone()).collect();
    let bp: Vec<Vec<u8>> = full_phase2.iter().map(|(_l, b)| b.clone()).collect();
    assert_eq!(bt, bp);
}

#[test]
fn replay_from_empty_store_returns_nothing() {
    let (_dir, storage) = open_sealing();
    let (frames, cursor) = storage.replay_from(None, 0).unwrap();
    assert!(frames.is_empty());
    assert_eq!(cursor, None);
}

// ════════════════════════════════════════════════════════════════════
//  read_frame_bytes + batch  (L1450, L1569, L1607)
// ════════════════════════════════════════════════════════════════════

#[test]
fn read_frame_bytes_head_last_frame_bounds() {
    // L1450: the head-path `end > buf.len()` bound must accept the final frame in a
    // block (end == buf.len).
    let (_dir, mut storage) = open_head();
    let stream_hash = sh();
    let outs = append_batch_seqs(&mut storage, stream_hash, ID, 1..=3);
    assert!(storage.head.is_some());
    for (i, o) in outs.iter().enumerate() {
        let loc = o.location.expect("head location");
        let frame = storage.read_frame_bytes(loc.segment_seq, loc.offset).unwrap();
        let decoded = decode_frame_v1(&frame).unwrap();
        assert_eq!(decoded.payload_bytes, payload_for(i as u64 + 1));
    }
}

#[test]
fn read_frame_bytes_sealed_last_frame_roundtrip() {
    let (_dir, mut storage) = open_sealing();
    let stream_hash = sh();
    let outs = append_batch_seqs(&mut storage, stream_hash, ID, 1..=4);
    for (i, o) in outs.iter().enumerate() {
        let loc = o.location.expect("sealed location");
        let frame = storage.read_frame_bytes(loc.segment_seq, loc.offset).unwrap();
        let decoded = decode_frame_v1(&frame).unwrap();
        assert_eq!(decoded.payload_bytes, payload_for(i as u64 + 1));
    }
}

fn big(seq: u64) -> Vec<u8> {
    // ~1.6 MiB, distinct per seq so cross-block confusion is byte-detectable.
    let mut v = vec![(seq & 0xff) as u8; 1_600_000];
    v[0..8].copy_from_slice(&seq.to_le_bytes());
    v
}

fn append_big_batch(
    s: &mut ShardStorage,
    stream_hash: u64,
    id: &str,
    seqs: std::ops::RangeInclusive<u64>,
) -> Vec<AppendOutcome> {
    let owned: Vec<(String, Vec<u8>)> = seqs.map(|k| (eid(k), big(k))).collect();
    let inputs: Vec<AppendEventInput> = owned.iter().map(|(i, p)| evin(i, p)).collect();
    s.append_batch(stream_hash, 0, T, TY, id, "2026-02-06T00:00:01Z", &inputs)
        .unwrap()
}

#[test]
fn read_frame_bytes_batch_sealed_block_and_segment_caching() {
    // Segment A: 3 big frames spanning 2 blocks. Segment B: 1 big frame (block 0).
    // A batch that hits (cache-hit, diff-seg-same-block, same-seg-diff-block) must
    // return each frame identical to the single-read path (L1607 cache key).
    let (_dir, mut storage) = open_sealing();
    let stream_hash = sh();
    let a = append_big_batch(&mut storage, stream_hash, ID, 1..=3);
    let seg_a = a[0].location.unwrap().segment_seq;
    assert!(
        storage.segment_trailers_by_seq[&seg_a].blocks.len() >= 2,
        "segment A must span >=2 blocks to exercise the block cache"
    );
    let b = append_big_batch(&mut storage, stream_hash, ID, 4..=4);

    let la0 = a[0].location.unwrap();
    let la1 = a[1].location.unwrap();
    let la2 = a[2].location.unwrap();
    let lb0 = b[0].location.unwrap();

    // Order: A.f0 (load), B.f0 (diff seg, same block idx), A.f1 (back to A block0),
    // A.f2 (same seg, different block).
    let locations = vec![la0, lb0, la1, la2];
    let packed = storage.read_frame_bytes_batch(&locations).unwrap();
    assert_eq!(packed.len(), 4);
    for (loc, frame) in locations.iter().zip(packed.iter()) {
        let single = storage.read_frame_bytes(loc.segment_seq, loc.offset).unwrap();
        assert_eq!(frame, &single, "batch frame must equal single-read frame");
        decode_frame_v1(frame).unwrap();
    }
    // Confirm block 1's frame really differs from block 0's (guards cache-key kills).
    assert_ne!(packed[0], packed[3]);
}

#[test]
fn read_frame_bytes_batch_head_block_caching() {
    // Head with 3 big frames across 2 blocks; a batch across the block boundary must
    // reload the second block (L1569 head cache key).
    let (_dir, mut storage) = open_head();
    let stream_hash = sh();
    let outs = append_big_batch(&mut storage, stream_hash, ID, 1..=3);
    assert!(
        storage.head.as_ref().unwrap().blocks.len() >= 2,
        "head must span >=2 blocks to exercise the head block cache"
    );
    let locs: Vec<FrameLocation> = outs.iter().map(|o| o.location.unwrap()).collect();
    let packed = storage.read_frame_bytes_batch(&locs).unwrap();
    assert_eq!(packed.len(), 3);
    for (loc, frame) in locs.iter().zip(packed.iter()) {
        let single = storage.read_frame_bytes(loc.segment_seq, loc.offset).unwrap();
        assert_eq!(frame, &single);
    }
    assert_ne!(packed[0], packed[2], "block-0 and block-1 frames differ");
}

#[test]
fn read_frame_bytes_batch_packed_mixed_and_empty() {
    let (_dir, mut storage) = open_head();
    let stream_hash = sh();
    append_batch_seqs(&mut storage, stream_hash, ID, 1..=2);
    storage.force_seal_head().unwrap();
    let sealed: Vec<FrameLocation> = storage
        .read_stream(T, TY, ID, stream_hash, 1, 0)
        .unwrap()
        .into_iter()
        .map(|e| e.location)
        .collect();
    let head = append_batch_seqs(&mut storage, stream_hash, ID, 3..=4);
    let mut locs = sealed.clone();
    locs.extend(head.iter().map(|o| o.location.unwrap()));

    let packed = storage.read_frame_bytes_batch_packed(&locs).unwrap();
    assert_eq!(packed.frame_offsets.len(), 4);
    assert_eq!(packed.frame_lens.len(), 4);
    assert_eq!(
        packed.frame_bytes,
        packed.frame_lens.iter().map(|l| *l as u64).sum::<u64>()
    );

    let batch = storage.read_frame_bytes_batch(&locs).unwrap();
    for (loc, frame) in locs.iter().zip(batch.iter()) {
        assert_eq!(frame, &storage.read_frame_bytes(loc.segment_seq, loc.offset).unwrap());
    }

    let empty = storage.read_frame_bytes_batch_packed(&[]).unwrap();
    assert!(empty.frames_blob.is_empty());
    assert_eq!(empty.frame_bytes, 0);
}

// ════════════════════════════════════════════════════════════════════
//  LZ4-coded sealed segments (block-read path in read_selected_tail_...)
// ════════════════════════════════════════════════════════════════════

#[test]
fn lz4_sealed_tail_and_replay_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let opts = ShardStorageOptions {
        record_block_codec: corecrux_segment::RECORD_BLOCK_CODEC_LZ4_V1,
        ..Default::default()
    };
    let mut storage = ShardStorage::open(dir.path(), 1, 1, opts).unwrap();
    let stream_hash = sh();
    append_each_seq(&mut storage, stream_hash, ID, 1..=5);
    for ti in storage.segment_trailers_by_seq.values() {
        for b in &ti.blocks {
            assert_eq!(b.codec, corecrux_segment::RECORD_BLOCK_CODEC_LZ4_V1);
        }
    }
    let tail = storage.read_tail(T, TY, ID, stream_hash, 3).unwrap();
    assert_events_exact(&tail, &[3, 4, 5]);
    let (frames, _e) = storage.replay_from_sealed(None, 0).unwrap();
    assert_eq!(frames.len(), 5);
    let range = storage.read_stream(T, TY, ID, stream_hash, 2, 2).unwrap();
    assert_events_exact(&range, &[2, 3]);
}
