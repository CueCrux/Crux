// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Discovery, attribution and erasure of segments that carry no `.ccxi`.
//!
//! Every assertion here fails on the pre-M4 daemon, where the startup scan
//! matched `.ccxi` and tenant membership was read from its doc table: a
//! `.ccxi`-less segment was undiscovered, un-attributable, and — because
//! `reclaim_segment` looked the segment up in the loaded set — silently
//! un-erasable. A fact-only segment cannot have a `.ccxi` (there is no prose to
//! index), so this is the GDPR-relevant case, not a corner one.

use std::path::{Path, PathBuf};

use corecrux_frame::{canonical_header_bytes_v1, CanonicalHeaderV1};
use corecrux_retrieval::index_manager::IndexManager;
use corecrux_segment::{build_segment_v1, FrameInput, SegmentId};

fn canonical_header(tenant_id: &str, seq: u64) -> Vec<u8> {
    canonical_header_bytes_v1(&CanonicalHeaderV1 {
        tenant_id: tenant_id.to_string(),
        stream_id: format!("stream-{tenant_id}"),
        stream_type: "note".to_string(),
        seq,
        event_id: format!("evt-{seq}"),
        occurred_at: "2026-08-09T00:00:00Z".to_string(),
        ingested_at: "2026-08-09T00:00:01Z".to_string(),
        event_type: "note.created".to_string(),
        content_type: "text/plain".to_string(),
        payload_len: 7,
        payload_hash: [0u8; 32],
    })
}

/// A real sealed segment holding one frame per entry in `tenants`.
fn sealed_segment(segment_seq: u64, tenants: &[&str]) -> Vec<u8> {
    let headers: Vec<Vec<u8>> = tenants
        .iter()
        .enumerate()
        .map(|(i, t)| canonical_header(t, i as u64 + 1))
        .collect();
    let frames: Vec<FrameInput<'_>> = tenants
        .iter()
        .enumerate()
        .map(|(i, _)| FrameInput {
            stream_hash: 900 + i as u64,
            seq: i as u64 + 1,
            event_id: "evt",
            header_hash: [1u8; 32],
            payload_hash: [2u8; 32],
            header_bytes: &headers[i],
            payload_bytes: b"payload",
        })
        .collect();

    build_segment_v1(0, 1, segment_seq, SegmentId([7u8; 16]), 1, 2, &frames)
        .expect("build segment")
        .bytes
}

fn hex16(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Write a `.ccxseg` under the storage naming scheme, plus the dense companion
/// a sealed segment carries, and return the `.ccxseg` path.
fn write_segment(dir: &Path, segment_seq: u64, tenants: &[&str]) -> PathBuf {
    let stem = format!("seg-{segment_seq:020}-{}", hex16(&[7u8; 16]));
    let path = dir.join(format!("{stem}.ccxseg"));
    std::fs::write(&path, sealed_segment(segment_seq, tenants)).expect("write ccxseg");
    std::fs::write(dir.join(format!("{stem}.ccxe")), vec![0u8; 128]).expect("write ccxe");
    path
}

fn tenant_hash(tenant_id: &str) -> u64 {
    xxhash_rust::xxh64::xxh64(tenant_id.as_bytes(), 0)
}

#[test]
fn scan_discovers_a_segment_with_no_ccxi() {
    let tmp = tempfile::tempdir().unwrap();
    write_segment(tmp.path(), 11, &["acme", "acme"]);

    let mut mgr = IndexManager::new();
    assert_eq!(
        mgr.scan_and_load(tmp.path()).unwrap(),
        1,
        "the .ccxseg is the discovery key"
    );
    assert_eq!(mgr.segment_count(), 1);
    assert_eq!(mgr.segments_without_ccxi(), vec![11]);
    // It contributes no BM25 reader — discovery is not the same as a lane.
    assert!(mgr.readers().is_empty());
    assert_eq!(mgr.total_docs(), 2, "docs come from the segment's own frames");
}

#[test]
fn a_ccxi_less_segment_is_attributed_to_its_tenant() {
    let tmp = tempfile::tempdir().unwrap();
    write_segment(tmp.path(), 12, &["acme", "acme", "acme"]);

    let mut mgr = IndexManager::new();
    mgr.scan_and_load(tmp.path()).unwrap();

    let footprint = mgr.tenant_footprint(tenant_hash("acme"));
    assert_eq!(footprint.segments.len(), 1);
    assert_eq!(footprint.docs, 3);
    assert_eq!(footprint.mixed_segments, 0);
    assert_eq!(footprint.unattributable_segments, 0);
    assert!(footprint.segments[0].whole_tenant, "reclaimable: no co-tenant present");
    assert!(
        footprint.bytes > 0,
        "the on-disk group is sized, so a reclaim can be costed"
    );

    // A co-tenant of the same segment sees it too, and neither may delete it.
    let other = mgr.tenant_footprint(tenant_hash("globex"));
    assert!(other.segments.is_empty(), "globex has no frames in this segment");
}

#[test]
fn a_shared_ccxi_less_segment_is_never_whole_tenant() {
    let tmp = tempfile::tempdir().unwrap();
    write_segment(tmp.path(), 13, &["acme", "globex"]);

    let mut mgr = IndexManager::new();
    mgr.scan_and_load(tmp.path()).unwrap();

    let footprint = mgr.tenant_footprint(tenant_hash("acme"));
    assert_eq!(footprint.docs, 1);
    assert_eq!(footprint.mixed_segments, 1);
    assert!(
        !footprint.segments[0].whole_tenant,
        "deleting this group would erase globex's frame too"
    );
}

#[test]
fn erasure_removes_the_whole_file_group_of_a_ccxi_less_segment() {
    let tmp = tempfile::tempdir().unwrap();
    let ccxseg = write_segment(tmp.path(), 14, &["acme"]);
    let ccxe = ccxseg.with_extension("ccxe");

    let mut mgr = IndexManager::new();
    mgr.scan_and_load(tmp.path()).unwrap();

    let freed = mgr.reclaim_segment(14).expect("reclaim");
    assert!(freed > 0, "pre-M4 this returned Ok(0) and left the files on disk");
    assert!(!ccxseg.exists(), "the segment itself must go");
    assert!(!ccxe.exists(), "and every companion sharing its stem");
    assert_eq!(mgr.segment_count(), 0);
}

#[test]
fn an_unreadable_segment_is_discovered_and_reported_rather_than_ignored() {
    let tmp = tempfile::tempdir().unwrap();
    let stem = format!("seg-{:020}-{}", 15, hex16(&[7u8; 16]));
    std::fs::write(tmp.path().join(format!("{stem}.ccxseg")), vec![0xAAu8; 9000]).unwrap();

    let mut mgr = IndexManager::new();
    mgr.scan_and_load(tmp.path()).unwrap();

    assert_eq!(
        mgr.segment_count(),
        1,
        "still discovered — invisible is the worse failure"
    );
    let footprint = mgr.tenant_footprint(tenant_hash("acme"));
    assert_eq!(footprint.unattributable_segments, 1);
    assert!(
        footprint.segments.is_empty(),
        "never claimed for a tenant it cannot be shown to belong to"
    );
}

#[test]
fn refresh_from_disk_picks_up_a_segment_sealed_after_the_last_scan() {
    let tmp = tempfile::tempdir().unwrap();
    write_segment(tmp.path(), 16, &["acme"]);

    let mut mgr = IndexManager::new();
    mgr.scan_and_load(tmp.path()).unwrap();
    assert_eq!(mgr.segment_count(), 1);

    // Sealed behind the manager's back, as an ingest between two erasure calls
    // would be.
    write_segment(tmp.path(), 17, &["acme"]);
    assert_eq!(mgr.refresh_from_disk(), 1);

    let footprint = mgr.tenant_footprint(tenant_hash("acme"));
    assert_eq!(
        footprint.segments.len(),
        2,
        "erasure enumerates from disk, not from memory"
    );
}

#[test]
fn a_companion_written_after_the_scan_is_picked_up_on_the_next_one() {
    // The seal path renames the `.ccxseg` into place and *then* writes the
    // `.ccxi`. A scan landing in that window registers the segment with no
    // reader; if "already known" meant "never look again", it would serve no
    // BM25 lane for the rest of the process's life.
    let tmp = tempfile::tempdir().unwrap();
    write_segment(tmp.path(), 18, &["acme"]);

    let mut mgr = IndexManager::new();
    mgr.scan_and_load(tmp.path()).unwrap();
    assert!(mgr.readers().is_empty(), "the companion had not been written yet");

    let mut builder = corecrux_index::CcxiBuilder::new(0, 18, 100);
    builder.add_document(0, "terraform drift detection", 0, tenant_hash("acme"));
    std::fs::write(
        tmp.path().join(format!("seg-{:020}-{}.ccxi", 18, hex16(&[7u8; 16]))),
        builder.build(),
    )
    .unwrap();

    assert_eq!(mgr.scan_and_load(tmp.path()).unwrap(), 1, "upgraded, not skipped");
    assert_eq!(mgr.readers().len(), 1);
    assert_eq!(mgr.segment_count(), 1, "upgraded in place — not a second entry");
    assert!(mgr.segments_without_ccxi().is_empty());
}

#[test]
fn a_ccxi_without_its_segment_is_still_loaded() {
    // A broken on-disk state, but one the pre-M4 scan served. Dropping it here
    // would take a corpus dark instead of reporting a problem.
    let tmp = tempfile::tempdir().unwrap();
    let mut builder = corecrux_index::CcxiBuilder::new(0, 21, 100);
    builder.add_document(0, "terraform drift detection", 0, tenant_hash("acme"));
    std::fs::write(
        tmp.path().join(format!("seg-{:020}-{}.ccxi", 21, hex16(&[7u8; 16]))),
        builder.build(),
    )
    .unwrap();

    let mut mgr = IndexManager::new();
    assert_eq!(mgr.scan_and_load(tmp.path()).unwrap(), 1);
    assert_eq!(mgr.readers().len(), 1);
}

#[test]
fn a_segment_with_both_companions_reads_its_tenants_from_the_ccxi() {
    // When a `.ccxi` exists it stays the doc table: the frame-header path is a
    // fallback for segments that have none, never a second opinion.
    let tmp = tempfile::tempdir().unwrap();
    write_segment(tmp.path(), 22, &["acme", "globex"]);
    let mut builder = corecrux_index::CcxiBuilder::new(0, 22, 100);
    builder.add_document(0, "terraform drift detection", 0, tenant_hash("acme"));
    builder.add_document(1, "kubernetes ingress", 100, tenant_hash("globex"));
    std::fs::write(
        tmp.path().join(format!("seg-{:020}-{}.ccxi", 22, hex16(&[7u8; 16]))),
        builder.build(),
    )
    .unwrap();

    let mut mgr = IndexManager::new();
    mgr.scan_and_load(tmp.path()).unwrap();
    assert_eq!(mgr.readers().len(), 1, "the .ccxi is loaded, not bypassed");
    assert!(mgr.segments_without_ccxi().is_empty());

    let footprint = mgr.tenant_footprint(tenant_hash("acme"));
    assert_eq!(footprint.docs, 1);
    assert_eq!(footprint.mixed_segments, 1);
}
