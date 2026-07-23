// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Mutation-killing tests for src/append.rs (ExecPlan crux-storage-mutation-burndown-2026-07-22).
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[allow(unused_imports)]
use crate::*;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

// ── Shared fixtures ─────────────────────────────────────────────────────────

const TENANT: &str = "t1";
const STYPE: &str = "s";
const OCCURRED: &str = "2026-02-06T00:00:00Z";
const INGESTED: &str = "2026-02-06T00:00:01Z";

fn shash(stream_id: &str) -> u64 {
    corecrux_frame::stream_hash_xxhash64(TENANT, STYPE, stream_id).unwrap()
}

fn ev<'a>(event_id: &'a str, payload: &'a [u8]) -> AppendEventInput<'a> {
    AppendEventInput {
        event_id,
        occurred_at: OCCURRED,
        event_type: "t",
        content_type: "application/octet-stream",
        payload_bytes: payload,
    }
}

/// UTF-8-text event so the `.ccxi` companion actually indexes it.
fn ev_text<'a>(event_id: &'a str, payload: &'a [u8]) -> AppendEventInput<'a> {
    AppendEventInput {
        event_id,
        occurred_at: OCCURRED,
        event_type: "t",
        content_type: "text/plain",
        payload_bytes: payload,
    }
}

fn open_storage(options: ShardStorageOptions) -> (tempfile::TempDir, ShardStorage) {
    let dir = tempfile::tempdir().unwrap();
    let storage = ShardStorage::open(dir.path(), 1, 1, options).unwrap();
    (dir, storage)
}

fn head_opts(max: usize) -> ShardStorageOptions {
    ShardStorageOptions {
        head_max_record_bytes: max,
        ..Default::default()
    }
}

fn append(s: &mut ShardStorage, sid: &str, expected: u64, evs: &[AppendEventInput<'_>]) -> Vec<AppendOutcome> {
    s.append_batch(shash(sid), expected, TENANT, STYPE, sid, INGESTED, evs)
        .unwrap()
}

fn prefix_of(s: &ShardStorage, event_id: &str) -> [u8; 16] {
    normalize_hash16_prefix(blake3_hash16(event_id.as_bytes()), s.options.event_id_hash_prefix_len)
}

/// Write a crafted `.ccxhead` file directly into the segments dir. `records` are
/// pre-encoded record byte-strings; `commit` (if any) appends a valid commit frame
/// covering exactly those records. Uses the real encoders — never re-implements the
/// mutated logic.
fn craft_head_file(
    root: &Path,
    shard_id: u32,
    epoch: u64,
    seq: u64,
    records: &[Vec<u8>],
    commit: Option<(u64, u64)>,
) -> PathBuf {
    let seg_id = deterministic_segment_id(epoch, seq);
    let header = corecrux_segment::SegmentHeaderV1 {
        flags: 1,
        shard_id,
        epoch,
        segment_seq: seq,
        segment_id: seg_id,
        created_at_unix_ns: 42,
    };
    let mut bytes = corecrux_segment::encode_segment_header_v1(&header).unwrap();
    let mut region: Vec<u8> = Vec::new();
    for r in records {
        region.extend_from_slice(r);
    }
    bytes.extend_from_slice(&region);
    if let Some((commit_id, commit_seq)) = commit {
        let marker_off = bytes.len();
        let region_crc = crc32c::crc32c(&region);
        let commit_offset = (marker_off + COMMIT_FRAME_LEN_V1) as u64;
        let cf = encode_commit_frame_v1(commit_id, commit_seq, commit_offset, region_crc);
        bytes.extend_from_slice(&cf);
    }
    let name = format!("seg-{seq:020}-{}.ccxhead", hex16(&seg_id.0));
    let path = ShardPaths::for_root(root, shard_id).segments_dir.join(name);
    std::fs::write(&path, &bytes).unwrap();
    path
}

/// Build a sealed segment whose single frame carries a header of exactly `header_len`
/// bytes (used to exercise the `header_bytes.len() < 32` guards on stored frames).
fn build_short_header_segment(seq: u64, stream_hash: u64, event_id: &str, header_len: usize) -> Vec<u8> {
    let hdr = vec![0u8; header_len];
    let frame = corecrux_segment::FrameInput {
        stream_hash,
        seq: 1,
        event_id,
        header_hash: [0u8; 32],
        payload_hash: [0u8; 32],
        header_bytes: &hdr,
        payload_bytes: b"",
    };
    let seg = corecrux_segment::build_segment_v1_with_block_codec(
        1,
        1,
        seq,
        deterministic_segment_id(1, seq),
        1,
        2,
        corecrux_segment::RECORD_BLOCK_CODEC_NONE_V1,
        &[frame],
    )
    .unwrap();
    seg.bytes
}

fn count_ccxi(s: &ShardStorage) -> usize {
    std::fs::read_dir(&s.paths.segments_dir)
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "ccxi"))
        .count()
}

// ── load_head_segment_from_disk ─────────────────────────────────────────────

// Kills 82:24 (< → ==, < → <=): a header-only head file (len == SEGMENT_HEADER_LEN)
// must pass the "too small" guard, be recognised as empty, and be removed — open() Ok.
#[test]
fn recover_header_only_head_is_removed() {
    let dir = tempfile::tempdir().unwrap();
    {
        let _s = ShardStorage::open(dir.path(), 1, 1, ShardStorageOptions::default()).unwrap();
    }
    let path = craft_head_file(dir.path(), 1, 1, 7, &[], None);
    assert_eq!(
        std::fs::metadata(&path).unwrap().len() as usize,
        corecrux_segment::SEGMENT_HEADER_LEN
    );
    let s = ShardStorage::open(dir.path(), 1, 1, ShardStorageOptions::default()).unwrap();
    assert!(!path.exists(), "header-only head must be removed on recovery");
    drop(s);
}

// Kills 88:49 (|| → &&): a head whose epoch mismatches (shard matches) must be rejected.
#[test]
fn recover_head_epoch_mismatch_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    {
        let _s = ShardStorage::open(dir.path(), 1, 1, ShardStorageOptions::default()).unwrap();
    }
    // shard_id matches (1), epoch does not (2 vs 1).
    craft_head_file(dir.path(), 1, 2, 7, &[], None);
    let res = ShardStorage::open(dir.path(), 1, 1, ShardStorageOptions::default());
    assert!(res.is_err(), "epoch-mismatched head must be rejected on open");
}

// Kills 155:43 (< → ==): a recovered frame whose decoded header is < 32 bytes must be
// treated as corruption (skipped), not fed into the `len - 32` slice (which would panic).
#[test]
fn recover_head_short_header_frame_is_skipped() {
    let dir = tempfile::tempdir().unwrap();
    {
        let _s = ShardStorage::open(dir.path(), 1, 1, ShardStorageOptions::default()).unwrap();
    }
    let frame = corecrux_segment::encode_frame_v1(&[0u8; 20], b"").unwrap();
    let path = craft_head_file(dir.path(), 1, 1, 7, &[frame], Some((1, 1)));
    // Original: short-header frame skipped -> no committed frames -> head removed -> Ok.
    let s = ShardStorage::open(dir.path(), 1, 1, ShardStorageOptions::default()).unwrap();
    assert!(!path.exists());
    drop(s);
}

// Kills 210:55 / 211:36 (+ → - , + → *): next_seq recovered from head frames must be
// last_seq + 1 for both the first-event (or_insert) and later-event (and_modify) paths.
#[test]
fn recover_head_next_seq_per_stream() {
    let dir = tempfile::tempdir().unwrap();
    let sid_a = "a";
    let sid_b = "b";
    let sh_a = shash(sid_a);
    let sh_b = shash(sid_b);
    {
        let mut s = ShardStorage::open(dir.path(), 1, 1, head_opts(1 << 20)).unwrap();
        // stream A: exactly one event (exercises `or_insert`, line 211).
        append(&mut s, sid_a, 0, &[ev("a1", b"x")]);
        // stream B: two events in one batch (exercises `and_modify`, line 210).
        append(&mut s, sid_b, 0, &[ev("b1", b"x"), ev("b2", b"x")]);
    }
    let mut reopened = ShardStorage::open(dir.path(), 1, 1, head_opts(1 << 20)).unwrap();
    assert_eq!(
        *reopened.next_seq_by_stream.get(&sh_a).unwrap(),
        2,
        "single-event stream next_seq"
    );
    assert_eq!(
        *reopened.next_seq_by_stream.get(&sh_b).unwrap(),
        3,
        "two-event stream next_seq"
    );

    // Idempotency + seq assignment survived the reopen.
    let dup = append(&mut reopened, sid_a, 0, &[ev("a1", b"x")]);
    assert_eq!(dup[0].status, AppendStatus::DuplicateCommitted);
    assert_eq!(dup[0].seq, 1);
    let fresh = append(&mut reopened, sid_a, 2, &[ev("a2", b"x")]);
    assert_eq!(fresh[0].status, AppendStatus::Appended);
    assert_eq!(fresh[0].seq, 2);
    let read_b = reopened.read_stream(TENANT, STYPE, sid_b, sh_b, 0, 0).unwrap();
    assert_eq!(read_b.len(), 2);
}

// ── seal_head_segment ───────────────────────────────────────────────────────

// Kills 306:24 (< → ==, < → <=): sealing a freshly-opened (empty) head whose file is
// exactly SEGMENT_HEADER_LEN long must pass the "too small" guard and seal 0 frames.
#[test]
fn force_seal_empty_head_succeeds() {
    let (_d, mut s) = open_storage(head_opts(1 << 20));
    s.ensure_head_open().unwrap();
    let res = s.force_seal_head().unwrap();
    assert!(res.sealed);
    assert_eq!(res.frame_count, Some(0));
}

// Kills 446:21 (< → >) and 446:63 (== → !=): the seal-time TOC grouping loop must collapse
// all same-stream entries into a single directory ref (not one ref per entry).
#[test]
fn seal_head_groups_same_stream_into_one_ref() {
    let (_d, mut s) = open_storage(head_opts(1 << 20));
    let sid = "a";
    let sh = shash(sid);
    append(&mut s, sid, 0, &[ev("e1", b"x"), ev("e2", b"x"), ev("e3", b"x")]);
    let res = s.force_seal_head().unwrap();
    assert!(res.sealed);
    assert_eq!(res.frame_count, Some(3));
    assert_eq!(
        s.directory_by_stream.get(&sh).unwrap().len(),
        1,
        "three same-stream entries must form exactly one directory ref"
    );
}

// ── append_batch_with_stats: admission ──────────────────────────────────────

// Kills 617:25 (> → >=): a batch of exactly max_events_per_batch must be accepted.
#[test]
fn append_events_at_batch_limit_is_accepted() {
    let opts = ShardStorageOptions {
        max_events_per_batch: 2,
        ..Default::default()
    };
    let (_d, mut s) = open_storage(opts);
    let out = s
        .append_batch(
            shash("a"),
            0,
            TENANT,
            STYPE,
            "a",
            INGESTED,
            &[ev("e1", b"x"), ev("e2", b"y")],
        )
        .unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].status, AppendStatus::Appended);
}

// Kills 635:24 (> → >=): a batch whose byte total equals max_batch_bytes must be accepted.
#[test]
fn append_bytes_at_batch_limit_is_accepted() {
    // batch_bytes = payload(5) + min(event_id.len(2), max_event_id_bytes) = 7.
    let opts = ShardStorageOptions {
        max_batch_bytes: 7,
        ..Default::default()
    };
    let (_d, mut s) = open_storage(opts);
    let out = s
        .append_batch(shash("a"), 0, TENANT, STYPE, "a", INGESTED, &[ev("e1", b"hello")])
        .unwrap();
    assert_eq!(out[0].status, AppendStatus::Appended);
}

// Kills 654:32 (> → >=): a stream with tombstone_seq == 0 (but a checkpoint set) is NOT
// tombstoned and must accept appends.
#[test]
fn append_allowed_when_tombstone_seq_zero() {
    let (_d, mut s) = open_storage(ShardStorageOptions::default());
    let sid = "a";
    let sh = shash(sid);
    s.update_stream_meta(sh, 5, 0).unwrap(); // min_live_seq=5, tombstone_seq=0
    let out = append(&mut s, sid, 0, &[ev("e1", b"x")]);
    assert_eq!(out[0].status, AppendStatus::Appended);
}

// Kills 692:31 (> → >=) and 672:68 (> → == , > → >=): an event_id of length exactly
// max_event_id_bytes must be accepted, and re-appending it must dedupe via the cold path.
#[test]
fn append_event_id_at_max_len_accepted_and_dedupes_cold() {
    let opts = ShardStorageOptions {
        max_event_id_bytes: 2,
        idem_hot_capacity_entries: 0, // force the hot cache incomplete -> cold path
        ..Default::default()
    };
    let (_d, mut s) = open_storage(opts);
    let sid = "a";
    let first = append(&mut s, sid, 0, &[ev("ab", b"x")]); // len == max
    assert_eq!(first[0].status, AppendStatus::Appended, "len==max must be accepted");
    let second = append(&mut s, sid, 0, &[ev("ab", b"x")]);
    assert_eq!(
        second[0].status,
        AppendStatus::DuplicateCommitted,
        "len==max event must be included in the cold dedup scan"
    );
}

// Kills 738:46 (&& → ||): the cold lookup must fire only when the hot cache is incomplete
// AND this prefix has been seen. A brand-new event (unseen prefix) must not enter the cold
// scan (which, when segments exceed the scan cap, would raise spurious backpressure).
#[test]
fn append_new_event_skips_cold_scan() {
    let opts = ShardStorageOptions {
        idem_hot_capacity_entries: 0,
        cold_scan_max_segments: 1,
        ..Default::default()
    };
    let (_d, mut s) = open_storage(opts);
    append(&mut s, "a", 0, &[ev("a", b"x")]); // segment 1
    append(&mut s, "a", 0, &[ev("b", b"x")]); // segment 2 (2 > cap 1)
    let out = append(&mut s, "a", 0, &[ev("c", b"x")]); // brand-new prefix
    assert_eq!(
        out[0].status,
        AppendStatus::Appended,
        "new event must not trigger cold backpressure"
    );
}

// Kills 761:20 (delete !): when the cold scan is complete (scanned_all) and finds no true
// duplicate (prefix collision only), the event must be appended, not rejected.
#[test]
fn append_cold_scanned_all_no_dup_is_appended() {
    let opts = ShardStorageOptions {
        idem_hot_capacity_entries: 0,
        event_id_hash_prefix_len: 1, // 1-byte prefix -> engineered collisions
        cold_scan_max_segments: 256,
        ..Default::default()
    };
    let (_d, mut s) = open_storage(opts);
    let sid = "a";
    let base = "evt-a";
    let target = normalize_hash16_prefix(blake3_hash16(base.as_bytes()), 1);
    let mut collider = String::new();
    for i in 0..100_000u32 {
        let cand = format!("x{i}");
        if cand != base && normalize_hash16_prefix(blake3_hash16(cand.as_bytes()), 1) == target {
            collider = cand;
            break;
        }
    }
    assert!(!collider.is_empty(), "expected to find a 1-byte prefix collision");

    append(&mut s, sid, 0, &[ev(base, b"x")]); // sealed segment 1
    let out = append(&mut s, sid, 0, &[ev(&collider, b"x")]);
    assert_eq!(
        out[0].status,
        AppendStatus::Appended,
        "prefix-collision non-duplicate with a complete scan must be appended"
    );
}

// ── append_batch_with_stats: head-segment sizing (890) ──────────────────────

fn one_event_head_record_len() -> u64 {
    let (_d, mut s) = open_storage(head_opts(1 << 20));
    append(&mut s, "m", 0, &[ev("e1", b"hello")]);
    s.head.as_ref().unwrap().record_len
}

// Kills 890:33 (> → == , > → <) and 890:93 (> → ==): when a second batch strictly overflows
// max_head, the existing head is sealed first, so the two batches land in distinct segments.
#[test]
fn head_strict_overflow_seals_previous_head() {
    let r = one_event_head_record_len();
    let (_d, mut s) = open_storage(head_opts((r + 1) as usize));
    let o1 = append(&mut s, "a", 0, &[ev("e1", b"hello")]);
    let o2 = append(&mut s, "a", 0, &[ev("e2", b"hello")]);
    let seg1 = o1[0].location.unwrap().segment_seq;
    let seg2 = o2[0].location.unwrap().segment_seq;
    assert_ne!(
        seg1, seg2,
        "strict overflow must seal the previous head into its own segment"
    );
}

// Kills 890:93 (> → == , > → >=): at the exact boundary (sum == max_head) the seal-before is
// NOT taken, so both batches share one head (sealed together by the trailing threshold check).
#[test]
fn head_exact_boundary_does_not_seal_before() {
    let r = one_event_head_record_len();
    let (_d, mut s) = open_storage(head_opts((2 * r) as usize));
    let o1 = append(&mut s, "a", 0, &[ev("e1", b"hello")]);
    let o2 = append(&mut s, "a", 0, &[ev("e2", b"hello")]);
    let seg1 = o1[0].location.unwrap().segment_seq;
    let seg2 = o2[0].location.unwrap().segment_seq;
    assert_eq!(seg1, seg2, "exact boundary must not trigger a seal-before");
}

// Kills 1040:72 (&& → ||): head-path location patching must only touch outcomes whose seq
// matches; a rejected outcome (seq 0, location None) must keep location None.
#[test]
fn head_rejected_outcome_keeps_no_location() {
    let (_d, mut s) = open_storage(head_opts(1 << 20));
    let out = append(&mut s, "a", 0, &[ev("", b"x"), ev("e1", b"x")]);
    assert_eq!(out[0].status, AppendStatus::Rejected);
    assert!(
        out[0].location.is_none(),
        "rejected outcome must not be assigned a frame location"
    );
    assert_eq!(out[1].status, AppendStatus::Appended);
    assert!(out[1].location.is_some());
}

// ── append_batch_with_stats: phase-2 seal path ──────────────────────────────

// Kills 1119:39 (delete !): with build_ccxi enabled and text payload, the .ccxi companion
// must be built.
#[test]
fn phase2_builds_ccxi_when_enabled() {
    let opts = ShardStorageOptions {
        build_ccxi: true,
        ..Default::default()
    };
    let (_d, mut s) = open_storage(opts);
    s.append_batch(
        shash("a"),
        0,
        TENANT,
        STYPE,
        "a",
        INGESTED,
        &[ev_text("e1", b"hello world")],
    )
    .unwrap();
    assert_eq!(count_ccxi(&s), 1, "ccxi companion must be built when enabled");
}

// Kills 1119:36 (&& → ||): with build_ccxi disabled, no .ccxi companion may be built.
#[test]
fn phase2_no_ccxi_when_disabled() {
    let (_d, mut s) = open_storage(ShardStorageOptions::default());
    s.append_batch(
        shash("a"),
        0,
        TENANT,
        STYPE,
        "a",
        INGESTED,
        &[ev_text("e1", b"hello world")],
    )
    .unwrap();
    assert_eq!(count_ccxi(&s), 0, "no ccxi companion may be built when disabled");
}

// Kills 1217:21 (< → >) and 1217:63 (== → !=): the phase-2 TOC grouping loop must collapse
// same-stream entries into a single directory ref.
#[test]
fn phase2_groups_same_stream_into_one_ref() {
    let (_d, mut s) = open_storage(ShardStorageOptions::default());
    let sid = "a";
    let sh = shash(sid);
    append(&mut s, sid, 0, &[ev("e1", b"x"), ev("e2", b"x"), ev("e3", b"x")]);
    assert_eq!(s.directory_by_stream.get(&sh).unwrap().len(), 1);
}

// Kills 1274:69 (&& → ||): phase-2 location patching must only touch matching-seq outcomes;
// a rejected outcome (seq 0) must keep location None.
#[test]
fn phase2_rejected_outcome_keeps_no_location() {
    let (_d, mut s) = open_storage(ShardStorageOptions::default());
    let out = append(&mut s, "a", 0, &[ev("", b"x"), ev("e1", b"x")]);
    assert_eq!(out[0].status, AppendStatus::Rejected);
    assert!(out[0].location.is_none());
    assert_eq!(out[1].status, AppendStatus::Appended);
    assert!(out[1].location.is_some());
}

// ── lookup_duplicate_cold_batch ─────────────────────────────────────────────

// Kills 1346:17 (delete field scanned_all): an empty needed-prefix lookup must report
// scanned_all == true (nothing to scan), else the caller raises spurious backpressure.
#[test]
fn cold_batch_empty_prefixes_reports_scanned_all() {
    let (_d, s) = open_storage(ShardStorageOptions::default());
    let cold = s.lookup_duplicate_cold_batch(shash("a"), &HashSet::new()).unwrap();
    assert!(cold.scanned_all, "empty-prefix cold batch must be marked fully scanned");
}

// Kills 1358:38 (!= → ==) and 1362:24 (delete !): the head-frame scan must find a duplicate
// whose stream matches and whose prefix is needed.
#[test]
fn cold_batch_finds_head_duplicate() {
    let (_d, mut s) = open_storage(head_opts(1 << 20));
    let sid = "a";
    let sh = shash(sid);
    append(&mut s, sid, 0, &[ev("dup", b"x")]);
    let p = prefix_of(&s, "dup");
    let mut needed = HashSet::new();
    needed.insert(p);
    let cold = s.lookup_duplicate_cold_batch(sh, &needed).unwrap();
    assert!(cold.find(p, "dup").is_some(), "head-frame duplicate must be found");
}

// Kills 1406:33 (== → !=): with one sealed segment and scan cap >= total, scanned_all == true.
#[test]
fn cold_batch_sealed_reports_scanned_all() {
    let (_d, mut s) = open_storage(ShardStorageOptions::default());
    let sid = "a";
    let sh = shash(sid);
    append(&mut s, sid, 0, &[ev("dup", b"x")]);
    let p = prefix_of(&s, "dup");
    let mut needed = HashSet::new();
    needed.insert(p);
    let cold = s.lookup_duplicate_cold_batch(sh, &needed).unwrap();
    assert!(cold.scanned_all);
    assert!(cold.find(p, "dup").is_some());
}

// Kills 1434:47 (< → ==): a stored frame with a < 32-byte header must be rejected, not fed
// into the `len - 32` slice (which would panic under the mutant).
#[test]
fn cold_batch_short_header_frame_errors() {
    let (_d, mut s) = open_storage(ShardStorageOptions::default());
    let sh = shash("craft");
    let bytes = build_short_header_segment(77, sh, "z", 20);
    s.apply_replicated_segment_v1(&bytes).unwrap();
    let mut needed = HashSet::new();
    needed.insert(prefix_of(&s, "z"));
    assert!(s.lookup_duplicate_cold_batch(sh, &needed).is_err());
}

// Kills 1434:47 (< → <=): a 32-byte header passes the "too small" guard and fails at the
// canonical-header parse, yielding the parse-error message (not the too-small message).
#[test]
fn cold_batch_empty_canonical_header_parse_error() {
    let (_d, mut s) = open_storage(ShardStorageOptions::default());
    let sh = shash("craft");
    let bytes = build_short_header_segment(77, sh, "z", 32);
    s.apply_replicated_segment_v1(&bytes).unwrap();
    let mut needed = HashSet::new();
    needed.insert(prefix_of(&s, "z"));
    let err = s.lookup_duplicate_cold_batch(sh, &needed).unwrap_err();
    assert!(
        format!("{err}").contains("failed to parse stored canonical header bytes"),
        "expected canonical parse error, got: {err}"
    );
}

// ── lookup_duplicate_cold (direct pub(crate) calls) ─────────────────────────

fn idem_key(s: &ShardStorage, sid: &str, event_id: &str) -> IdemKey {
    IdemKey {
        stream_hash: shash(sid),
        event_id_hash16: prefix_of(s, event_id),
    }
}

// Kills 1479:38 / 1483:29 / 1493:37 (!= → ==): the head-frame path must return the duplicate.
#[test]
fn cold_finds_head_duplicate() {
    let (_d, mut s) = open_storage(head_opts(1 << 20));
    let sid = "a";
    append(&mut s, sid, 0, &[ev("dup", b"x")]);
    let key = idem_key(&s, sid, "dup");
    let found = s.lookup_duplicate_cold(&key, "dup").unwrap();
    let out = found.expect("head duplicate must be found");
    assert_eq!(out.status, AppendStatus::DuplicateCommitted);
    assert_eq!(out.seq, 1);
}

// Kills 1510:18 / 1515:16 / 1524:33 (== → !=), 1532:34 / 1539:25 / 1559:36 (!= → ==),
// 1545:47 (< → >), and 1551:64 (- → + , - → /): the sealed-segment path must return the
// duplicate for a real stored frame.
#[test]
fn cold_finds_sealed_duplicate() {
    let (_d, mut s) = open_storage(ShardStorageOptions::default());
    let sid = "a";
    append(&mut s, sid, 0, &[ev("dup", b"x")]);
    let key = idem_key(&s, sid, "dup");
    let found = s.lookup_duplicate_cold(&key, "dup").unwrap();
    let out = found.expect("sealed duplicate must be found");
    assert_eq!(out.status, AppendStatus::DuplicateCommitted);
    assert_eq!(out.seq, 1);
}

// Kills 1524:33 (== → !=): a completed scan that finds no duplicate must return Ok(None),
// not backpressure.
#[test]
fn cold_sealed_scanned_all_no_dup_returns_none() {
    let (_d, mut s) = open_storage(ShardStorageOptions::default());
    let sid = "a";
    append(&mut s, sid, 0, &[ev("dup", b"x")]);
    let key = idem_key(&s, sid, "absent");
    let res = s.lookup_duplicate_cold(&key, "absent").unwrap();
    assert!(res.is_none(), "fully-scanned miss must be Ok(None)");
}

// Kills 1545:47 (< → ==): a stored frame with a < 32-byte header must error, not panic.
#[test]
fn cold_short_header_frame_errors() {
    let (_d, mut s) = open_storage(ShardStorageOptions::default());
    let sh = shash("craft");
    let bytes = build_short_header_segment(77, sh, "z", 20);
    s.apply_replicated_segment_v1(&bytes).unwrap();
    let key = IdemKey {
        stream_hash: sh,
        event_id_hash16: prefix_of(&s, "z"),
    };
    assert!(s.lookup_duplicate_cold(&key, "z").is_err());
}

// Kills 1545:47 (< → <=): a 32-byte header must reach the canonical parse error.
#[test]
fn cold_empty_canonical_header_parse_error() {
    let (_d, mut s) = open_storage(ShardStorageOptions::default());
    let sh = shash("craft");
    let bytes = build_short_header_segment(77, sh, "z", 32);
    s.apply_replicated_segment_v1(&bytes).unwrap();
    let key = IdemKey {
        stream_hash: sh,
        event_id_hash16: prefix_of(&s, "z"),
    };
    let err = s.lookup_duplicate_cold(&key, "z").unwrap_err();
    assert!(
        format!("{err}").contains("failed to parse stored canonical header bytes"),
        "expected canonical parse error, got: {err}"
    );
}

// ── read_canonical_and_hashes_for_location ──────────────────────────────────

fn short_header_loc(s: &mut ShardStorage, header_len: usize) -> FrameLocation {
    let sh = shash("craft");
    let bytes = build_short_header_segment(77, sh, "z", header_len);
    let (_h, _th, entries, _f) = corecrux_segment::decode_segment_v1(&bytes).unwrap();
    let offset = entries[0].file_offset as u64;
    s.apply_replicated_segment_v1(&bytes).unwrap();
    FrameLocation {
        shard_id: 1,
        epoch: 1,
        segment_seq: 77,
        offset,
    }
}

// Kills 1600:39 (< → ==): a < 32-byte header must error rather than underflow-panic.
#[test]
fn read_canonical_short_header_errors() {
    let (_d, mut s) = open_storage(ShardStorageOptions::default());
    let loc = short_header_loc(&mut s, 20);
    assert!(s.read_canonical_and_hashes_for_location(loc).is_err());
}

// Kills 1600:39 (< → <=): a 32-byte header must reach the canonical parse error.
#[test]
fn read_canonical_empty_header_parse_error() {
    let (_d, mut s) = open_storage(ShardStorageOptions::default());
    let loc = short_header_loc(&mut s, 32);
    let err = s.read_canonical_and_hashes_for_location(loc).unwrap_err();
    assert!(
        format!("{err}").contains("failed to parse stored canonical header bytes"),
        "expected canonical parse error, got: {err}"
    );
}

// ── filter_extents_live ─────────────────────────────────────────────────────

// Kills 1686:26 (< → == , < → <=): an extent whose max_seq equals the cut is still live.
#[test]
fn filter_extents_live_keeps_extent_at_cut() {
    let (_d, mut s) = open_storage(ShardStorageOptions::default());
    let sid = "a";
    let sh = shash(sid);
    s.update_stream_meta(sh, 5, 0).unwrap(); // cut = 5
    let extents = [DirExtentV1 {
        stream_hash: sh,
        min_seq: 1,
        max_seq: 5,
        segment_seq: 1,
    }];
    let live = s.filter_extents_live(&extents);
    assert_eq!(live.len(), 1, "extent with max_seq == cut must remain live");
    assert_eq!(live[0].max_seq, 5);
}

// ── rebuild_directory_from_runs ─────────────────────────────────────────────

// Kills 1805:34 (< → == , < → <=): on rebuild, an extent whose max_seq equals the cut must
// be retained so the boundary event stays readable.
#[test]
fn rebuild_keeps_extent_at_cut() {
    let dir = tempfile::tempdir().unwrap();
    let sid = "a";
    let sh = shash(sid);
    {
        let mut s = ShardStorage::open(dir.path(), 1, 1, ShardStorageOptions::default()).unwrap();
        append(
            &mut s,
            sid,
            0,
            &[
                ev("e1", b"x"),
                ev("e2", b"x"),
                ev("e3", b"x"),
                ev("e4", b"x"),
                ev("e5", b"x"),
            ],
        );
        s.update_stream_meta(sh, 5, 0).unwrap(); // cut = 5 == max_seq
    }
    let reopened = ShardStorage::open(dir.path(), 1, 1, ShardStorageOptions::default()).unwrap();
    let got = reopened.read_stream(TENANT, STYPE, sid, sh, 0, 0).unwrap();
    assert_eq!(
        got.len(),
        1,
        "boundary event (seq == cut) must survive directory rebuild"
    );
    assert_eq!(got[0].seq, 5);
}

// ── bootstrap_directory_runs_on_open ────────────────────────────────────────

// Kills 1832:37 (&& → ||): a normal reopen (dir runs already present) must not republish
// duplicate directory runs.
#[test]
fn bootstrap_no_duplicate_runs_on_reopen() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut s = ShardStorage::open(dir.path(), 1, 1, ShardStorageOptions::default()).unwrap();
        append(&mut s, "a", 0, &[ev("e1", b"x")]);
        assert_eq!(s.dir_runs.len(), 1);
    }
    let reopened = ShardStorage::open(dir.path(), 1, 1, ShardStorageOptions::default()).unwrap();
    assert_eq!(reopened.dir_runs.len(), 1, "reopen must not duplicate directory runs");
}

// ── update_stream_meta ──────────────────────────────────────────────────────

// Kills 1886:46 (< → <=): re-asserting the current checkpoint value (equal, not smaller) is
// allowed. Kills 1895:48 (< → <=): likewise for the tombstone value.
#[test]
fn update_stream_meta_idempotent_reassert_is_ok() {
    let (_d, mut s) = open_storage(ShardStorageOptions::default());
    let sh = shash("a");
    s.update_stream_meta(sh, 10, 5).unwrap();
    // checkpoint equal (10 == 10) with a no-op tombstone -> allowed (kills 1886 <=).
    assert!(s.update_stream_meta(sh, 10, 0).is_ok());
    // tombstone equal (5 == 5) with a no-op checkpoint -> allowed (kills 1895 <=).
    assert!(s.update_stream_meta(sh, 0, 5).is_ok());
}

// Kills 1908:30 (== → !=): a genuine no-op update (nothing changes) must early-return WITHOUT
// creating a stream-meta entry.
#[test]
fn update_stream_meta_no_change_creates_no_entry() {
    let (_d, mut s) = open_storage(ShardStorageOptions::default());
    let sh = shash("a");
    let res = s.update_stream_meta(sh, 0, 0).unwrap();
    assert_eq!(res, (0, 0));
    assert!(
        !s.stream_meta.contains_key(&sh),
        "a no-op update must not materialise a stream-meta entry"
    );
}
