// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.
// Mutation-killing tests for src/integrity.rs (ExecPlan crux-storage-mutation-burndown-2026-07-22).
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[allow(unused_imports)]
use crate::*;

use std::sync::Mutex;

// The append/seal path touches process-global state indirectly; serialise like tests.rs.
static INTEGRITY_TEST_LOCK: Mutex<()> = Mutex::new(());

fn lock() -> std::sync::MutexGuard<'static, ()> {
    INTEGRITY_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

const OCCURRED: &str = "2026-02-06T00:00:00Z";
const INGESTED: &str = "2026-02-06T00:00:01Z";

fn open_storage(opts: ShardStorageOptions) -> (tempfile::TempDir, ShardStorage) {
    let dir = tempfile::tempdir().unwrap();
    let storage = ShardStorage::open(dir.path(), 1, 1, opts).unwrap();
    (dir, storage)
}

/// Append a single-event batch on a fresh stream (`expected_next_seq = 0`). With default
/// options each call seals its own segment; with a large `head_max_record_bytes` it stays
/// in the head segment.
fn append_event(storage: &mut ShardStorage, stream_id: &str, event_id: &str, payload: &[u8]) {
    let stream_hash = corecrux_frame::stream_hash_xxhash64("t", "s", stream_id).unwrap();
    storage
        .append_batch(
            stream_hash,
            0,
            "t",
            "s",
            stream_id,
            INGESTED,
            &[AppendEventInput {
                event_id,
                occurred_at: OCCURRED,
                event_type: "t",
                content_type: "application/octet-stream",
                payload_bytes: payload,
            }],
        )
        .unwrap();
}

/// Independently sum the sealed-segment trailer block byte counts (compressed, uncompressed).
fn sealed_expected_bytes(storage: &ShardStorage) -> (u64, u64) {
    let mut comp = 0u64;
    let mut uncomp = 0u64;
    for seg in &storage.segments_in_order {
        let ti = storage.segment_trailers_by_seq.get(&seg.segment_seq).unwrap();
        comp += ti.blocks.iter().map(|b| b.compressed_len as u64).sum::<u64>();
        uncomp += ti.blocks.iter().map(|b| b.uncompressed_len as u64).sum::<u64>();
    }
    (comp, uncomp)
}

fn sealed_expected_blocks(storage: &ShardStorage) -> u64 {
    storage
        .segments_in_order
        .iter()
        .map(|seg| {
            storage
                .segment_trailers_by_seq
                .get(&seg.segment_seq)
                .unwrap()
                .blocks
                .len() as u64
        })
        .sum()
}

// ─────────────────────────────────────────────────────────────────────────
// TASK 1 — behavioural pins for replay_scan_stats_all / integrity_scan_stats_all.
//
// The byte/segment/block accumulators start at 0, so a `+= x` mutated to `*= x`
// collapses the running total to 0 (or a product). Each test independently recomputes
// the expected totals and asserts exact equality, killing every `*=` accumulator mutant.
// Each test also drives the per-segment inner batching loop, whose `i += 1` mutated to
// `i *= 1` never advances the cursor -> non-terminating scan -> caught by timeout.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn replay_scan_sealed_only_reports_exact_totals() {
    let _g = lock();
    let (_dir, mut storage) = open_storage(ShardStorageOptions::default());
    append_event(&mut storage, "seg-a", "e1", b"payload-a");
    append_event(&mut storage, "seg-b", "e2", b"payload-bbbbbbbb");
    assert!(storage.head.is_none(), "default options seal each append");
    assert_eq!(storage.segments_in_order.len(), 2);

    let (exp_comp, exp_uncomp) = sealed_expected_bytes(&storage);
    assert!(exp_comp > 0 && exp_uncomp > 0);

    let stats = storage.replay_scan_stats_all(8 * 1024 * 1024).expect("replay scan");
    assert_eq!(stats.total_segments, 2);
    assert_eq!(stats.total_frames, 2);
    // Kills L51 (`total_compressed_bytes += .. ` -> `*=`; sealed-only total would be 0).
    assert_eq!(stats.total_compressed_bytes, exp_comp);
    // Kills L52 (`total_uncompressed_bytes += ..` -> `*=`).
    assert_eq!(stats.total_uncompressed_bytes, exp_uncomp);
    // replay intentionally never populates total_blocks.
    assert_eq!(stats.total_blocks, 0);
}

#[test]
fn replay_scan_head_only_reports_exact_totals() {
    let _g = lock();
    let opts = ShardStorageOptions {
        head_max_record_bytes: 1024 * 1024,
        ..Default::default()
    };
    let (_dir, mut storage) = open_storage(opts);
    append_event(&mut storage, "head-a", "e1", b"aaaaaaaa");
    append_event(&mut storage, "head-b", "e2", b"bbbbbbbb");
    assert!(
        storage.segments_in_order.is_empty(),
        "nothing sealed with large head budget"
    );
    let head = storage.head.as_ref().expect("head present");
    let exp_comp: u64 = head.blocks.iter().map(|b| b.compressed_len as u64).sum();
    let exp_uncomp: u64 = head.blocks.iter().map(|b| b.uncompressed_len as u64).sum();
    assert!(exp_comp > 0 && exp_uncomp > 0);

    let stats = storage.replay_scan_stats_all(8 * 1024 * 1024).expect("replay scan");
    assert_eq!(stats.total_segments, 1);
    assert_eq!(stats.total_frames, 2);
    // Kills L99 (head `total_compressed_bytes += ..` -> `*=`; head-only total would be 0).
    assert_eq!(stats.total_compressed_bytes, exp_comp);
    // Kills L100 (head `total_uncompressed_bytes += ..` -> `*=`).
    assert_eq!(stats.total_uncompressed_bytes, exp_uncomp);
}

#[test]
fn integrity_scan_sealed_only_reports_exact_totals() {
    let _g = lock();
    let (_dir, mut storage) = open_storage(ShardStorageOptions::default());
    append_event(&mut storage, "iseg-a", "e1", b"payload-a");
    append_event(&mut storage, "iseg-b", "e2", b"payload-bbbbbbbb");
    assert_eq!(storage.segments_in_order.len(), 2);

    let (exp_comp, exp_uncomp) = sealed_expected_bytes(&storage);
    let exp_blocks = sealed_expected_blocks(&storage);
    assert!(exp_blocks > 0 && exp_comp > 0);

    let stats = storage
        .integrity_scan_stats_all(8 * 1024 * 1024)
        .expect("integrity scan");
    // Kills L175 (`total_segments += 1` -> `*= 1`; stays 0).
    assert_eq!(stats.total_segments, 2);
    // Kills L176 (`total_blocks += ..` -> `*=`; stays 0).
    assert_eq!(stats.total_blocks, exp_blocks);
    // Kills L177 (`total_compressed_bytes += ..` -> `*=`).
    assert_eq!(stats.total_compressed_bytes, exp_comp);
    // Kills L178 (`total_uncompressed_bytes += ..` -> `*=`).
    assert_eq!(stats.total_uncompressed_bytes, exp_uncomp);
    assert_eq!(stats.total_frames, 2);
}

#[test]
fn integrity_scan_head_only_reports_exact_totals() {
    let _g = lock();
    let opts = ShardStorageOptions {
        head_max_record_bytes: 1024 * 1024,
        ..Default::default()
    };
    let (_dir, mut storage) = open_storage(opts);
    append_event(&mut storage, "ihead-a", "e1", b"aaaaaaaa");
    append_event(&mut storage, "ihead-b", "e2", b"bbbbbbbb");
    assert!(storage.segments_in_order.is_empty());
    let head = storage.head.as_ref().expect("head present");
    let exp_comp: u64 = head.blocks.iter().map(|b| b.compressed_len as u64).sum();
    let exp_uncomp: u64 = head.blocks.iter().map(|b| b.uncompressed_len as u64).sum();
    let exp_blocks = head.blocks.len() as u64;
    assert!(exp_blocks > 0 && exp_comp > 0);

    // Under L243 (head outer `while i < head.blocks.len()` -> `==`/`>`) the head loop never
    // runs, so scanned=0 != expected(2) and integrity_scan returns Err; `.expect` catches it.
    let stats = storage
        .integrity_scan_stats_all(8 * 1024 * 1024)
        .expect("integrity scan");
    // Kills L234 (head `total_segments += 1` -> `*= 1`; stays 0).
    assert_eq!(stats.total_segments, 1);
    // Kills L235 (head `total_blocks += ..` -> `*=`; stays 0).
    assert_eq!(stats.total_blocks, exp_blocks);
    // Kills L236 (head `total_compressed_bytes += ..` -> `*=`).
    assert_eq!(stats.total_compressed_bytes, exp_comp);
    // Kills L237 (head `total_uncompressed_bytes += ..` -> `*=`).
    assert_eq!(stats.total_uncompressed_bytes, exp_uncomp);
    // Reinforces L243: a valid head must scan its frames and succeed.
    assert_eq!(stats.total_frames, 2);
}

// ─────────────────────────────────────────────────────────────────────────
// TASK 2 — strict chain-verification characterization.
//
// `verify-store --strict` (corecruxctl) runs `integrity_scan_stats_all` then
// `verify_segment_hashes_all`. The latter re-decodes each manifest-listed segment and
// compares the decoded footer's `segment_hash` to the manifest entry — per segment, in
// isolation. It performs NO predecessor-link walk, NO segment_seq continuity/ordering
// check, and NO seal-receipt/signature verification (the predecessor link lives only in
// the ephemeral SegmentSealMaterialV1 seal receipt and is never persisted in SegmentMeta;
// signing is the corecrux-receipts/daemon layer, not storage). These tests pin the ACTUAL
// (weak) behavior and mark each gap; they are the acceptance tests for a future hardening.
// ─────────────────────────────────────────────────────────────────────────
mod strict_chain_characterization {
    use super::*;

    fn sealed_chain(n: usize) -> (tempfile::TempDir, ShardStorage) {
        let (dir, mut storage) = open_storage(ShardStorageOptions::default());
        for i in 0..n {
            append_event(&mut storage, &format!("chain-{i}"), &format!("e{i}"), b"x");
        }
        assert_eq!(storage.segments_in_order.len(), n);
        (dir, storage)
    }

    // (a) A segment removed from the middle of the chain (its manifest entry dropped) is
    //     UNDETECTED: the remaining segments each still hash-match their own manifest record.
    #[test]
    fn a_deleted_segment_midchain_passes_strict_hash_scan() {
        let _g = lock();
        let (_dir, mut storage) = sealed_chain(3);
        let seqs: Vec<u64> = storage.segments_in_order.iter().map(|s| s.segment_seq).collect();

        let baseline = storage.verify_segment_hashes_all().expect("intact chain verifies");
        assert_eq!(baseline.verified_segments, 3);

        // Drop the middle segment's manifest entry -> a hole between seq[0] and seq[2].
        storage.segments_in_order.remove(1);
        storage.segment_trailers_by_seq.remove(&seqs[1]);

        // GAP: strict verification has no predecessor-link / seq-continuity walk, so the
        // mid-chain hole is invisible. SHOULD: reject a non-contiguous segment chain
        // (a missing predecessor for seq[2]).
        let after = storage
            .verify_segment_hashes_all()
            .expect("UNDETECTED: mid-chain deletion passes strict verification");
        assert_eq!(after.verified_segments, 2);
    }

    // (a′) Boundary: if the segment FILE is deleted but the manifest entry KEPT, strict
    //      verification DOES reject (File read fails). Documents what IS caught today.
    #[test]
    fn a_deleted_segment_file_still_referenced_is_rejected() {
        let _g = lock();
        let (dir, storage) = sealed_chain(2);
        let victim = dir
            .path()
            .join("shard-0001")
            .join(&storage.segments_in_order[1].relative_path);
        std::fs::remove_file(&victim).expect("delete the on-disk segment file");

        let err = storage
            .verify_segment_hashes_all()
            .expect_err("a manifest-referenced but missing segment file must be rejected");
        // Reading the absent file surfaces as an IO-classified storage error.
        assert!(matches!(err, StorageError::Io { .. }), "unexpected error: {err:?}");
    }

    // (b) Reordering the manifest/segment list is UNDETECTED: each entry still matches its
    //     own body hash regardless of position.
    #[test]
    fn b_reordered_segments_pass_strict_hash_scan() {
        let _g = lock();
        let (_dir, mut storage) = sealed_chain(3);
        let seqs_before: Vec<u64> = storage.segments_in_order.iter().map(|s| s.segment_seq).collect();
        assert!(
            seqs_before.windows(2).all(|w| w[0] < w[1]),
            "sealed in monotonically increasing seq order"
        );

        storage.segments_in_order.reverse();

        // GAP: verify_segment_hashes_all never asserts segment_seq is monotonic/contiguous
        // across the walk, so an out-of-order (replayed / rolled-back) manifest passes.
        // SHOULD: reject when segment_seq is not strictly increasing.
        let stats = storage
            .verify_segment_hashes_all()
            .expect("UNDETECTED: reordered segments pass strict verification");
        assert_eq!(stats.verified_segments, 3);
    }

    // (c) A broken predecessor link / spliced chain position is UNDETECTED: strict
    //     verification compares only the body hash, never the recorded chain position.
    #[test]
    fn c_broken_predecessor_link_passes_strict_hash_scan() {
        let _g = lock();
        let (_dir, mut storage) = sealed_chain(2);

        // The chain WAS created with seg[1].previous_segment_hash == seg[0].segment_hash, but
        // that link lives only in the ephemeral seal receipt and is not persisted. Rewrite
        // seg[1]'s recorded seq to a bogus, non-adjacent value (a spliced predecessor
        // position). Body + body hash are untouched, and this now disagrees with the file's
        // own decoded footer seq.
        storage.segments_in_order[1].segment_seq = 9_999;

        // GAP: verify compares footer.segment_hash vs manifest hash only; it never checks
        // that manifest segment_seq matches the decoded footer seq, nor that seqs chain from
        // one segment to the next. SHOULD: walk previous_segment_hash/seq and reject a link
        // that does not chain to the prior segment.
        let stats = storage
            .verify_segment_hashes_all()
            .expect("UNDETECTED: mislinked predecessor seq passes strict verification");
        assert_eq!(stats.verified_segments, 2);
    }

    // (d) Seal-receipt SIGNATURES are not reachable from storage's verify path at all: the
    //     seal receipt is produced at seal time, never signed or persisted by storage.
    #[test]
    fn d_seal_signature_is_not_reachable_from_storage_verify_path() {
        let _g = lock();
        let (_dir, mut storage) = open_storage(ShardStorageOptions::default());
        let (_, stats) = storage
            .append_batch_with_stats(
                corecrux_frame::stream_hash_xxhash64("t", "s", "sig").unwrap(),
                0,
                "t",
                "s",
                "sig",
                INGESTED,
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: OCCURRED,
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap();
        let receipt = stats.seal_receipt.expect("seal receipt material produced at seal time");
        // A chainable seal receipt exists, but it is never signed/persisted by storage.
        assert_ne!(receipt.material_hash(), [0u8; 32]);

        // GAP: there is no seal-signature to be "invalid" within storage's verify path.
        // verify_segment_hashes_all + integrity_scan_stats_all rehash bodies only; neither
        // has a hook that would reject a segment with a missing/forged seal signature.
        // SHOULD (future): persist the signed seal receipt and verify its Ed25519 (CROWN)
        // signature + predecessor link during strict verification.
        assert_eq!(storage.verify_segment_hashes_all().unwrap().verified_segments, 1);
        assert_eq!(
            storage
                .integrity_scan_stats_all(8 * 1024 * 1024)
                .unwrap()
                .total_segments,
            1
        );
    }
}
