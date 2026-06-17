// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Unit + integration tests for `corecrux-storage` — manifest round-trips, append/seal/replay cycles, companions.

use super::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::companions::build_ccxi_companion;
    use crate::manifest::{load_manifest_records, validate_manifest_header};
    use corecrux_frame::{canonical_header_bytes_v1, compute_header_hash, compute_payload_hash, CanonicalHeaderV1};
    use corecrux_segment::FrameMetaV1;

    // Serialises tests that touch process-global state. Acquired poison-tolerant
    // (`unwrap_or_else(PoisonError::into_inner)`) so ONE panicking test does not
    // poison the mutex and cascade `PoisonError` panics across every other test,
    // masking the real failure (testing-system audit 2026-06-17, M6).
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // ── ShardPaths::for_root ────────────────────────────────────────

    #[test]
    fn shard_paths_for_root_layout() {
        let paths = ShardPaths::for_root(Path::new("/data"), 7);
        assert_eq!(paths.shard_dir, PathBuf::from("/data/shard-0007"));
        assert_eq!(paths.lock_path, PathBuf::from("/data/shard-0007/LOCK"));
        assert_eq!(paths.manifest_path, PathBuf::from("/data/shard-0007/MANIFEST"));
        assert_eq!(paths.segments_dir, PathBuf::from("/data/shard-0007/segments"));
        assert_eq!(paths.directory_dir, PathBuf::from("/data/shard-0007/directory"));
        assert_eq!(paths.projections_dir, PathBuf::from("/data/shard-0007/projections"));
        assert_eq!(paths.tmp_dir, PathBuf::from("/data/shard-0007/tmp"));
        assert_eq!(paths.quarantine_dir, PathBuf::from("/data/shard-0007/quarantine"));
    }

    #[test]
    fn shard_paths_for_root_zero_padded() {
        let paths = ShardPaths::for_root(Path::new("/x"), 1);
        assert_eq!(paths.shard_dir, PathBuf::from("/x/shard-0001"));
        let paths = ShardPaths::for_root(Path::new("/x"), 9999);
        assert_eq!(paths.shard_dir, PathBuf::from("/x/shard-9999"));
    }

    // ── ShardStorageOptions defaults ─────────────────────────────────

    #[test]
    fn shard_storage_options_default_values() {
        let opts = ShardStorageOptions::default();
        assert_eq!(opts.max_events_per_batch, 1024);
        assert_eq!(opts.max_batch_bytes, 16 * 1024 * 1024);
        assert_eq!(opts.max_event_id_bytes, 128);
        assert_eq!(opts.idem_hot_capacity_entries, 100_000);
        assert_eq!(opts.event_id_hash_prefix_len, 16);
        assert_eq!(opts.cold_scan_max_segments, 256);
        assert_eq!(opts.head_max_record_bytes, 0);
        assert_eq!(opts.record_block_codec, corecrux_segment::RECORD_BLOCK_CODEC_NONE_V1);
        assert!(!opts.enable_directory_compaction);
        assert_eq!(opts.dir_l0_max_runs, 8);
        assert_eq!(opts.append_group_commit_batches, 1);
        assert_eq!(opts.append_group_commit_max_delay_ms, 0);
        assert!(!opts.build_ccxi);
    }

    // ── Manifest constants ──────────────────────────────────────────

    #[test]
    fn manifest_constants_stable() {
        assert_eq!(MANIFEST_MAGIC_CCMF, 0x464D_4343);
        assert_eq!(MANIFEST_VERSION_V1, 1);
        assert_eq!(MANIFEST_HEADER_LEN, 256);
    }

    // ── Dirrun constants ────────────────────────────────────────────

    #[test]
    fn dirrun_constants_stable() {
        assert_eq!(DIRRUN_MAGIC_CCDR, 0x5244_4343);
        assert_eq!(DIRRUN_VERSION_V1, 1);
        assert_eq!(DIRRUN_HEADER_LEN, 4096);
        assert_eq!(DIRRUN_PARTITIONS_V1, 256);
        assert_eq!(DIRRUN_PARTITION_TABLE_OFFSET_V1, 64);
        assert_eq!(DIRRUN_PARTITION_ENTRY_LEN_V1, 12);
        assert_eq!(DIREXTENT_LEN_V1, 32);
    }

    // ── encode/decode dir extent roundtrip ──────────────────────────

    #[test]
    fn encode_decode_dir_extent_roundtrip() {
        let extent = DirExtentV1 {
            stream_hash: 0xDEAD_BEEF_1234_5678,
            min_seq: 10,
            max_seq: 99,
            segment_seq: 42,
        };
        let bytes = encode_dir_extent_v1(extent);
        assert_eq!(bytes.len(), DIREXTENT_LEN_V1);
        let decoded = decode_dir_extent_v1(&bytes).unwrap();
        assert_eq!(decoded, extent);
    }

    // ── encode/decode dir run roundtrip ─────────────────────────────

    #[test]
    fn encode_decode_dir_run_empty_roundtrip() {
        let bytes = encode_dir_run_v1(12345, &[]).unwrap();
        let decoded = decode_dir_run_v1(&bytes).unwrap();
        assert_eq!(decoded.created_at_unix_ns, 12345);
        assert_eq!(decoded.record_count, 0);
        for part in &decoded.partitions {
            assert!(part.is_empty());
        }
    }

    #[test]
    fn encode_decode_dir_run_with_extents_roundtrip() {
        let extents = vec![
            DirExtentV1 {
                stream_hash: 0x00,
                min_seq: 1,
                max_seq: 5,
                segment_seq: 1,
            },
            DirExtentV1 {
                stream_hash: 0x01,
                min_seq: 1,
                max_seq: 3,
                segment_seq: 2,
            },
            DirExtentV1 {
                stream_hash: 0xFF,
                min_seq: 10,
                max_seq: 20,
                segment_seq: 3,
            },
        ];
        let bytes = encode_dir_run_v1(99999, &extents).unwrap();
        let decoded = decode_dir_run_v1(&bytes).unwrap();
        assert_eq!(decoded.created_at_unix_ns, 99999);
        assert_eq!(decoded.record_count, 3);
    }

    #[test]
    fn encode_dir_run_deduplicates_same_key_extents() {
        let extents = vec![
            DirExtentV1 {
                stream_hash: 0x42,
                min_seq: 10,
                max_seq: 20,
                segment_seq: 1,
            },
            DirExtentV1 {
                stream_hash: 0x42,
                min_seq: 5,
                max_seq: 25,
                segment_seq: 1,
            },
        ];
        let bytes = encode_dir_run_v1(0, &extents).unwrap();
        let decoded = decode_dir_run_v1(&bytes).unwrap();
        // Should deduplicate: merged min_seq=5, max_seq=25
        assert_eq!(decoded.record_count, 1);
        let partition = dirrun_partition_v1(0x42);
        assert_eq!(decoded.partitions[partition].len(), 1);
        assert_eq!(decoded.partitions[partition][0].min_seq, 5);
        assert_eq!(decoded.partitions[partition][0].max_seq, 25);
    }

    // ── dirrun_partition_v1 masks low 8 bits ────────────────────────

    #[test]
    fn dirrun_partition_v1_range() {
        // All values should be in 0..256
        for i in 0u64..=512 {
            let p = dirrun_partition_v1(i);
            assert!(p < DIRRUN_PARTITIONS_V1, "partition {p} out of range for hash {i}");
        }
        assert_eq!(dirrun_partition_v1(0x00), 0);
        assert_eq!(dirrun_partition_v1(0xFF), 255);
        assert_eq!(dirrun_partition_v1(0x100), 0);
        assert_eq!(dirrun_partition_v1(0x1FF), 255);
    }

    // ── dir_extent_key_cmp ordering ─────────────────────────────────

    #[test]
    fn dir_extent_key_cmp_equal_elements() {
        let a = DirExtentV1 {
            stream_hash: 1,
            min_seq: 0,
            max_seq: 0,
            segment_seq: 5,
        };
        let b = DirExtentV1 {
            stream_hash: 1,
            min_seq: 99,
            max_seq: 99,
            segment_seq: 5,
        };
        assert_eq!(dir_extent_key_cmp(&a, &b), std::cmp::Ordering::Equal);
    }

    #[test]
    fn dir_extent_key_cmp_different_stream_hash() {
        let a = DirExtentV1 {
            stream_hash: 1,
            min_seq: 0,
            max_seq: 0,
            segment_seq: 1,
        };
        let b = DirExtentV1 {
            stream_hash: 2,
            min_seq: 0,
            max_seq: 0,
            segment_seq: 1,
        };
        assert_eq!(dir_extent_key_cmp(&a, &b), std::cmp::Ordering::Less);
        assert_eq!(dir_extent_key_cmp(&b, &a), std::cmp::Ordering::Greater);
    }

    // ── should_skip_startup_dirrun_bootstrap ─────────────────────────

    #[test]
    fn should_skip_startup_dirrun_bootstrap_cases() {
        assert!(!should_skip_startup_dirrun_bootstrap(false, 0));
        assert!(!should_skip_startup_dirrun_bootstrap(false, 999_999));
        assert!(!should_skip_startup_dirrun_bootstrap(true, 0));
        assert!(!should_skip_startup_dirrun_bootstrap(
            true,
            STARTUP_DIRRUN_BOOTSTRAP_SEGMENT_LIMIT_V1
        ));
        assert!(should_skip_startup_dirrun_bootstrap(
            true,
            STARTUP_DIRRUN_BOOTSTRAP_SEGMENT_LIMIT_V1 + 1
        ));
    }

    // ── StorageError display strings ────────────────────────────────

    #[test]
    fn storage_error_display_variants() {
        let err = StorageError::InvalidArgument {
            code: "BAD".to_string(),
            msg: "bad input".to_string(),
        };
        assert!(err.to_string().contains("invalid argument"));
        assert!(err.to_string().contains("BAD"));

        let err = StorageError::FailedPrecondition {
            code: "PRE".to_string(),
            msg: "not ready".to_string(),
        };
        assert!(err.to_string().contains("failed precondition"));

        let err = StorageError::ResourceExhausted {
            code: "RES".to_string(),
            msg: "too many".to_string(),
            retry_after_ms: Some(1000),
        };
        assert!(err.to_string().contains("resource exhausted"));

        let err = StorageError::Internal {
            msg: "oops".to_string(),
        };
        assert!(err.to_string().contains("internal error"));

        let err = StorageError::Io {
            msg: "disk fail".to_string(),
        };
        assert!(err.to_string().contains("io error"));

        let err = StorageError::ManifestHeaderInvalid {
            msg: "corrupt".to_string(),
        };
        assert!(err.to_string().contains("manifest header invalid"));

        let err = StorageError::ManifestCrcMismatch {
            expected: 0xAA,
            actual: 0xBB,
        };
        assert!(err.to_string().contains("manifest crc mismatch"));

        let err = StorageError::ManifestRecordCrcMismatch {
            expected: 0xCC,
            actual: 0xDD,
        };
        assert!(err.to_string().contains("manifest record crc mismatch"));

        let err = StorageError::ManifestRecordInvalid {
            msg: "bad record".to_string(),
        };
        assert!(err.to_string().contains("manifest record invalid"));
    }

    // ── SegmentMeta fields ──────────────────────────────────────────

    #[test]
    fn segment_meta_clone_and_debug() {
        let meta = SegmentMeta {
            level: 0,
            shard_id: 1,
            epoch: 1,
            segment_seq: 42,
            segment_id: corecrux_segment::SegmentId([0u8; 16]),
            relative_path: "segments/seg.ccxseg".to_string(),
            file_len: 1024,
            created_at_unix_ns: 100,
            sealed_at_unix_ns: 200,
            toc_offset: 512,
            toc_len: 64,
            toc_entry_count: 5,
            min_stream_hash: 0,
            min_seq: 1,
            max_stream_hash: u64::MAX,
            max_seq: 10,
            segment_hash: [0xAA; 32],
        };
        let cloned = meta.clone();
        assert_eq!(cloned.segment_seq, 42);
        assert_eq!(cloned.file_len, 1024);
        let dbg = format!("{:?}", meta);
        assert!(dbg.contains("segment_seq: 42"));
    }

    // ── parse_segment_seq_from_filename ──────────────────────────────

    #[test]
    fn parse_segment_seq_from_filename_various_valid() {
        // Format: seg-<20-digit-padded-seq>-<hash>.ccxseg
        assert_eq!(
            parse_segment_seq_from_filename("seg-00000000000000000042-abcd.ccxseg"),
            Some(42)
        );
        assert_eq!(
            parse_segment_seq_from_filename("seg-00000000000000000001-efgh.ccxseg"),
            Some(1)
        );
        assert_eq!(
            parse_segment_seq_from_filename("seg-00000000000000999999-ijkl.ccxseg"),
            Some(999999)
        );
    }

    #[test]
    fn parse_segment_seq_from_filename_various_invalid() {
        assert_eq!(parse_segment_seq_from_filename("not-a-segment.txt"), None);
        assert_eq!(parse_segment_seq_from_filename("abc.ccxseg"), None);
        assert_eq!(parse_segment_seq_from_filename(""), None);
        assert_eq!(parse_segment_seq_from_filename("seg-short-hash.ccxseg"), None);
    }

    // ── deterministic_segment_id ────────────────────────────────────

    #[test]
    fn deterministic_segment_id_is_deterministic() {
        let a = deterministic_segment_id(1, 42);
        let b = deterministic_segment_id(1, 42);
        assert_eq!(a.0, b.0);
    }

    #[test]
    fn deterministic_segment_id_differs_for_different_inputs() {
        let a = deterministic_segment_id(1, 42);
        let b = deterministic_segment_id(1, 43);
        assert_ne!(a.0, b.0);
        let c = deterministic_segment_id(2, 42);
        assert_ne!(a.0, c.0);
    }

    // ── rejected_outcome ────────────────────────────────────────────

    #[test]
    fn rejected_outcome_fields() {
        let o = rejected_outcome("DUP", "duplicate event".to_string());
        assert_eq!(o.status, AppendStatus::Rejected);
        assert_eq!(o.error_code.as_deref(), Some("DUP"));
        assert_eq!(o.error_message.as_deref(), Some("duplicate event"));
        assert_eq!(o.seq, 0);
    }

    // ── compute_write_confirmation_receipt_hash ─────────────────────

    #[test]
    fn write_confirmation_receipt_hash_is_deterministic() {
        let frames = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let h1 = compute_write_confirmation_receipt_hash(&frames);
        let h2 = compute_write_confirmation_receipt_hash(&frames);
        assert_eq!(h1, h2);
    }

    #[test]
    fn write_confirmation_receipt_hash_varies_with_input() {
        let a = compute_write_confirmation_receipt_hash(&[vec![1, 2, 3]]);
        let b = compute_write_confirmation_receipt_hash(&[vec![4, 5, 6]]);
        assert_ne!(a, b);
    }

    // ── SealResultV1 ────────────────────────────────────────────────

    #[test]
    fn seal_result_v1_fields() {
        let r = SealResultV1 {
            sealed: true,
            segment_seq: Some(42),
            frame_count: Some(100),
            seal_duration_secs: 0.5,
            seal_receipt: None,
        };
        assert!(r.sealed);
        assert_eq!(r.segment_seq, Some(42));

        let not_sealed = SealResultV1 {
            sealed: false,
            segment_seq: None,
            frame_count: None,
            seal_duration_secs: 0.0,
            seal_receipt: None,
        };
        assert!(!not_sealed.sealed);
    }

    // ── ManifestSegmentCatalogV1 ────────────────────────────────────

    #[test]
    fn manifest_segment_catalog_v1_empty() {
        let cat = ManifestSegmentCatalogV1 {
            shard_id: 1,
            epoch: 1,
            manifest_end: 256,
            segments: Vec::new(),
        };
        assert!(cat.segments.is_empty());
        assert_eq!(cat.manifest_end, 256);
    }

    // ── decode_dir_run_v1 bad version ──────────────────────────────

    #[test]
    fn decode_dir_run_v1_bad_version() {
        let mut bytes = encode_dir_run_v1(0, &[]).unwrap();
        // Corrupt version at offset 4..6
        bytes[4] = 99;
        bytes[5] = 0;
        let err = decode_dir_run_v1(&bytes).unwrap_err();
        assert!(err.to_string().contains("bad version"));
    }

    #[test]
    fn decode_dir_run_v1_bad_partitions() {
        let mut bytes = encode_dir_run_v1(0, &[]).unwrap();
        // Corrupt partitions at offset 12..16
        bytes[12] = 1;
        bytes[13] = 0;
        bytes[14] = 0;
        bytes[15] = 0;
        // Also fix the CRC
        let crc = crc32c::crc32c(&bytes[..DIRRUN_HEADER_LEN - 4]);
        bytes[DIRRUN_HEADER_LEN - 4..DIRRUN_HEADER_LEN].copy_from_slice(&crc.to_le_bytes());
        let err = decode_dir_run_v1(&bytes).unwrap_err();
        assert!(err.to_string().contains("bad partitions"));
    }

    fn open_test_storage(options: ShardStorageOptions) -> (tempfile::TempDir, ShardStorage) {
        let dir = tempfile::tempdir().unwrap();

        let storage = ShardStorage::open(dir.path(), 1, 1, options).unwrap();

        (dir, storage)
    }

    fn build_ccxi_test_frame(
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        seq: u64,
        event_id: &str,
        payload: &[u8],
        record_off: u32,
    ) -> (Vec<u8>, FrameMetaV1, u64) {
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).expect("stream hash");
        let payload_hash = compute_payload_hash(payload);
        let canonical = CanonicalHeaderV1 {
            tenant_id: tenant_id.to_string(),
            stream_id: stream_id.to_string(),
            stream_type: stream_type.to_string(),
            seq,
            event_id: event_id.to_string(),
            occurred_at: "2026-04-07T00:00:00Z".to_string(),
            ingested_at: "2026-04-07T00:00:01Z".to_string(),
            event_type: "evt.created".to_string(),
            content_type: "application/json".to_string(),
            payload_len: payload.len() as u32,
            payload_hash,
        };
        let canonical_bytes = canonical_header_bytes_v1(&canonical);
        let header_hash = compute_header_hash(&canonical_bytes);
        let mut header_bytes = canonical_bytes;
        header_bytes.extend_from_slice(&header_hash);
        let frame_bytes = corecrux_segment::encode_frame_v1(&header_bytes, payload).expect("encode frame");
        let meta = FrameMetaV1 {
            stream_hash,
            seq,
            record_off,
            frame_len: frame_bytes.len() as u32,
            payload_len: payload.len() as u32,
            event_id_hash16: [0; 16],
            header_digest8: [0; 8],
            payload_digest8: [0; 8],
        };
        (frame_bytes, meta, stream_hash)
    }

    fn build_ccxi_raw_frame(
        header_bytes: &[u8],
        payload: &[u8],
        stream_hash: u64,
        seq: u64,
        record_off: u32,
    ) -> (Vec<u8>, FrameMetaV1) {
        let frame_bytes = corecrux_segment::encode_frame_v1(header_bytes, payload).expect("encode frame");
        let meta = FrameMetaV1 {
            stream_hash,
            seq,
            record_off,
            frame_len: frame_bytes.len() as u32,
            payload_len: payload.len() as u32,
            event_id_hash16: [0; 16],
            header_digest8: [0; 8],
            payload_digest8: [0; 8],
        };
        (frame_bytes, meta)
    }

    #[test]
    fn startup_dirrun_bootstrap_skip_gate_is_stable() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        assert!(!should_skip_startup_dirrun_bootstrap(false, 10_000));
        assert!(!should_skip_startup_dirrun_bootstrap(
            true,
            STARTUP_DIRRUN_BOOTSTRAP_SEGMENT_LIMIT_V1
        ));
        assert!(should_skip_startup_dirrun_bootstrap(
            true,
            STARTUP_DIRRUN_BOOTSTRAP_SEGMENT_LIMIT_V1 + 1
        ));
    }

    #[allow(clippy::too_many_arguments)]
    fn build_test_replicated_segment(
        shard_id: u32,
        epoch: u64,
        segment_seq: u64,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        seq: u64,
        event_id: &str,
        payload: &[u8],
    ) -> corecrux_segment::SegmentBuildOutput {
        let payload_hash = compute_payload_hash(payload);
        let canonical = CanonicalHeaderV1 {
            tenant_id: tenant_id.to_string(),
            stream_id: stream_id.to_string(),
            stream_type: stream_type.to_string(),
            seq,
            event_id: event_id.to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            ingested_at: "2026-01-01T00:00:00Z".to_string(),
            event_type: "evt".to_string(),
            content_type: "application/octet-stream".to_string(),
            payload_len: payload.len() as u32,
            payload_hash,
        };
        let canonical_bytes = canonical_header_bytes_v1(&canonical);
        let header_hash = compute_header_hash(&canonical_bytes);
        let mut header_bytes = canonical_bytes.clone();
        header_bytes.extend_from_slice(&header_hash);
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).expect("stream hash");

        let frame = corecrux_segment::FrameInput {
            stream_hash,
            seq,
            event_id,
            header_hash,
            payload_hash,
            header_bytes: &header_bytes,
            payload_bytes: payload,
        };

        corecrux_segment::build_segment_v1_with_block_codec(
            shard_id,
            epoch,
            segment_seq,
            deterministic_segment_id(epoch, segment_seq),
            1,
            2,
            corecrux_segment::RECORD_BLOCK_CODEC_NONE_V1,
            &[frame],
        )
        .expect("build segment")
    }

    fn toc_entry(
        stream_hash: u64,
        seq: u64,
        block_id: u32,
        in_block_offset: u32,
        frame_len: u32,
    ) -> TocByOffsetEntryV1 {
        TocByOffsetEntryV1 {
            stream_hash,
            seq,
            block_id,
            in_block_offset,
            frame_len,
            flags: 0,
            event_id_hash16: [0; 16],
            header_digest8: [0; 8],
            payload_digest8: [0; 8],
        }
    }

    #[test]
    fn apply_replicated_segment_roundtrip_and_idempotent() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "tenant-a";
        let stream_type = "artifact";
        let stream_id = "1";
        let payload = b"replicated-payload".to_vec();
        let seg = build_test_replicated_segment(1, 1, 77, tenant_id, stream_type, stream_id, 1, "evt-1", &payload);

        let applied = storage
            .apply_replicated_segment_v1(&seg.bytes)
            .expect("apply replicated segment");
        assert!(applied.applied);
        assert_eq!(applied.segment_seq, 77);

        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();
        let got = storage
            .read_stream(tenant_id, stream_type, stream_id, stream_hash, 0, 32)
            .expect("read stream");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].seq, 1);
        assert_eq!(got[0].event_id, "evt-1");
        assert_eq!(got[0].payload, payload);

        let second = storage
            .apply_replicated_segment_v1(&seg.bytes)
            .expect("re-apply replicated segment");
        assert!(!second.applied);
        assert_eq!(second.segment_seq, 77);
    }

    #[test]
    fn apply_replicated_segment_conflict_rejected() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "tenant-a";
        let stream_type = "artifact";
        let stream_id = "1";

        let seg_ok =
            build_test_replicated_segment(1, 1, 88, tenant_id, stream_type, stream_id, 1, "evt-1", b"payload-a");
        storage
            .apply_replicated_segment_v1(&seg_ok.bytes)
            .expect("initial apply");

        let seg_conflict = build_test_replicated_segment(
            1,
            1,
            88, // same segment_seq, different contents -> conflict
            tenant_id,
            stream_type,
            stream_id,
            1,
            "evt-1",
            b"payload-b",
        );
        let err = storage
            .apply_replicated_segment_v1(&seg_conflict.bytes)
            .expect_err("expected conflict");
        match err {
            StorageError::FailedPrecondition { code, .. } => {
                assert_eq!(code, "REPLICATION_SEGMENT_CONFLICT");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn apply_replicated_segment_rejects_shard_mismatch() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let seg = build_test_replicated_segment(2, 1, 89, "tenant-a", "artifact", "1", 1, "evt-1", b"payload");
        let err = storage
            .apply_replicated_segment_v1(&seg.bytes)
            .expect_err("expected shard mismatch");
        match err {
            StorageError::FailedPrecondition { code, .. } => {
                assert_eq!(code, "REPLICATION_SHARD_MISMATCH");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn apply_replicated_segment_rejects_epoch_mismatch() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let seg = build_test_replicated_segment(1, 2, 90, "tenant-a", "artifact", "1", 1, "evt-1", b"payload");
        let err = storage
            .apply_replicated_segment_v1(&seg.bytes)
            .expect_err("expected epoch mismatch");
        match err {
            StorageError::FailedPrecondition { code, .. } => {
                assert_eq!(code, "REPLICATION_EPOCH_MISMATCH");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn read_segment_bytes_for_replication_roundtrip_and_missing_segment() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let seg = build_test_replicated_segment(1, 1, 91, "tenant-a", "artifact", "1", 1, "evt-1", b"payload");
        storage
            .apply_replicated_segment_v1(&seg.bytes)
            .expect("apply replicated segment");

        let (bytes, hash) = storage
            .read_segment_bytes_for_replication(91)
            .expect("read replicated bytes");
        assert_eq!(bytes, seg.bytes);
        assert_eq!(hash, seg.footer.segment_hash);

        let err = storage
            .read_segment_bytes_for_replication(999)
            .expect_err("missing segment should fail");
        match err {
            StorageError::ManifestRecordInvalid { msg } => {
                assert!(msg.contains("segment_seq 999 not found"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn read_segment_bytes_for_replication_detects_manifest_hash_mismatch() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let seg = build_test_replicated_segment(1, 1, 92, "tenant-a", "artifact", "1", 1, "evt-1", b"payload");
        storage
            .apply_replicated_segment_v1(&seg.bytes)
            .expect("apply replicated segment");

        storage.segments_by_seq.get_mut(&92).expect("segment meta").segment_hash = [0u8; 32];

        let err = storage
            .read_segment_bytes_for_replication(92)
            .expect_err("hash mismatch should fail");
        match err {
            StorageError::ManifestRecordInvalid { msg } => {
                assert!(msg.contains("segment hash mismatch for segment_seq 92"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn strict_scan_verifies_segment_hashes_and_detects_manifest_mismatch() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "tenant-a";
        let stream_type = "artifact";
        let stream_id = "strict-segment";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();
        storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"payload",
                }],
            )
            .expect("append sealed segment");

        let stats = storage.verify_segment_hashes_all().expect("strict scan");
        assert_eq!(stats.verified_segments, 1);
        assert_eq!(stats.verified_frames, 1);
        assert_eq!(stats.skipped_head_segments, 0);

        storage.segments_in_order[0].segment_hash = [0u8; 32];
        let err = storage
            .verify_segment_hashes_all()
            .expect_err("strict scan should catch manifest hash mismatch");
        match err {
            StorageError::ManifestRecordInvalid { msg } => {
                assert!(msg.contains("strict segment_hash mismatch for segment_seq"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn manifest_tail_truncation_ignores_partial_record() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("MANIFEST");

        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();

        let hdr = encode_manifest_header_v1(0, 1, 123).unwrap();
        f.write_all(&hdr).unwrap();

        let seg = SegmentMeta {
            level: 0,
            shard_id: 0,
            epoch: 1,
            segment_seq: 1,
            segment_id: SegmentId([1u8; 16]),
            relative_path: "segments/seg-00000000000000000001-00000000000000000000000000000000.ccxseg".to_string(),
            file_len: 999,
            created_at_unix_ns: 1,
            sealed_at_unix_ns: 2,
            toc_offset: 4096,
            toc_len: 128,
            toc_entry_count: 0,
            min_stream_hash: 0,
            min_seq: 0,
            max_stream_hash: 0,
            max_seq: 0,
            segment_hash: [2u8; 32],
        };
        let rec = encode_manifest_add_segment_v1(&seg).unwrap();
        let framed = frame_manifest_record(&rec);
        f.write_all(&framed).unwrap();

        // Write a partial trailing record (len+crc but missing body).
        f.write_all(&1234u32.to_le_bytes()).unwrap();
        f.write_all(&0u32.to_le_bytes()).unwrap();
        f.sync_all().unwrap();

        let (segs, end) = load_manifest_records(&mut f).unwrap();
        assert_eq!(segs.segments_by_seq.len(), 1);
        assert_eq!(end, (MANIFEST_HEADER_LEN + framed.len()) as u64);

        let len = f.metadata().unwrap().len();
        assert_eq!(len, end);
    }

    #[test]
    fn dirrun_encode_decode_roundtrip_v1() {
        let extents = vec![
            DirExtentV1 {
                stream_hash: 0x11,
                min_seq: 10,
                max_seq: 20,
                segment_seq: 7,
            },
            DirExtentV1 {
                stream_hash: 0x22,
                min_seq: 1,
                max_seq: 1,
                segment_seq: 8,
            },
            // Duplicate key should be merged deterministically.
            DirExtentV1 {
                stream_hash: 0x11,
                min_seq: 9,
                max_seq: 21,
                segment_seq: 7,
            },
        ];
        let bytes = encode_dir_run_v1(123, &extents).unwrap();
        let decoded = decode_dir_run_v1(&bytes).unwrap();
        assert_eq!(decoded.file_len as usize, bytes.len());
        assert_eq!(decoded.record_count, 2);

        // CRC mismatch should be detected.
        let mut bad = bytes.clone();
        bad[0] ^= 0xFF;
        assert!(decode_dir_run_v1(&bad).is_err());
    }

    #[test]
    fn directory_compaction_keeps_l0_runs_bounded() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let opts = ShardStorageOptions {
            enable_directory_compaction: true,
            dir_l0_max_runs: 2,
            ..Default::default()
        };
        let (_dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        for i in 0..10u32 {
            let eid = format!("e{i}");
            let payload = format!("p{i}").into_bytes();
            let events = [AppendEventInput {
                event_id: &eid,
                occurred_at: "2026-02-06T00:00:00Z",
                event_type: "t",
                content_type: "application/octet-stream",
                payload_bytes: payload.as_slice(),
            }];

            storage
                .append_batch(
                    stream_hash,
                    0,
                    tenant_id,
                    stream_type,
                    stream_id,
                    "2026-02-06T00:00:01Z",
                    &events,
                )
                .unwrap();
            storage.compact_directory_until_within_limits().unwrap();
        }

        let l0 = storage.dir_runs.values().filter(|r| r.key.level == 0).count();
        assert!(l0 <= 2, "expected l0<=2, got {l0}");

        let got = storage
            .read_stream(tenant_id, stream_type, stream_id, stream_hash, 1, 0)
            .unwrap();
        assert_eq!(got.len(), 10);
    }

    #[test]
    #[ignore]
    fn soak_ingest_under_compaction_pressure() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let secs: u64 = std::env::var("CORECRUX_SOAK_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(2);
        let max_events: u64 = std::env::var("CORECRUX_SOAK_MAX_EVENTS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(50_000);
        let streams: u64 = std::env::var("CORECRUX_SOAK_STREAMS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(16);
        let log_every: u64 = std::env::var("CORECRUX_SOAK_LOG_EVERY")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(5_000);
        let eq_check_every: u64 = std::env::var("CORECRUX_SOAK_EQ_CHECK_EVERY")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1_024);

        let opts = ShardStorageOptions {
            enable_directory_compaction: true,
            dir_l0_max_runs: 8,
            ..Default::default()
        };
        let l0_max = opts.dir_l0_max_runs;
        let (_dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";

        let start = std::time::Instant::now();
        let mut i: u64 = 0;
        let mut compaction_events_seen: u64 = 0;
        let mut eq_checks: u64 = 0;
        let mut eq_mismatches: u64 = 0;

        let tail_digest = |storage: &ShardStorage, stream_id: &str, stream_hash: u64| -> String {
            let events = storage
                .read_tail(tenant_id, stream_type, stream_id, stream_hash, 16)
                .unwrap_or_default();
            let mut h = blake3::Hasher::new();
            for e in &events {
                h.update(&e.seq.to_le_bytes());
                h.update(&(e.event_id.len() as u32).to_le_bytes());
                h.update(e.event_id.as_bytes());
                let ph = blake3::hash(&e.payload);
                h.update(ph.as_bytes());
                h.update(&e.location.shard_id.to_le_bytes());
                h.update(&e.location.epoch.to_le_bytes());
                h.update(&e.location.segment_seq.to_le_bytes());
                h.update(&e.location.offset.to_le_bytes());
            }
            h.finalize().to_hex().to_string()
        };
        while start.elapsed() < std::time::Duration::from_secs(secs) && i < max_events {
            let stream_id = format!("stream-{}", i % streams);
            let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, &stream_id).unwrap();

            let eid = format!("e{i}");
            let mut payload = vec![0u8; 32];
            payload[0..8].copy_from_slice(&i.to_le_bytes());
            let events = [AppendEventInput {
                event_id: &eid,
                occurred_at: "2026-02-06T00:00:00Z",
                event_type: "t",
                content_type: "application/octet-stream",
                payload_bytes: payload.as_slice(),
            }];

            storage
                .append_batch(
                    stream_hash,
                    0,
                    tenant_id,
                    stream_type,
                    &stream_id,
                    "2026-02-06T00:00:01Z",
                    &events,
                )
                .unwrap();
            let do_eq = eq_check_every > 0 && i > 0 && i.is_multiple_of(eq_check_every);
            let before = if do_eq {
                Some(tail_digest(&storage, &stream_id, stream_hash))
            } else {
                None
            };
            let compaction_events = storage.compact_directory_until_within_limits().unwrap();
            compaction_events_seen += compaction_events.len() as u64;
            if do_eq && !compaction_events.is_empty() {
                let after = tail_digest(&storage, &stream_id, stream_hash);
                eq_checks += 1;
                if before.expect("before digest") != after {
                    eq_mismatches += 1;
                }
            }
            i += 1;

            if log_every > 0 && i.is_multiple_of(log_every) {
                eprintln!(
                    "soak progress: events={} elapsed_s={:.1}",
                    i,
                    start.elapsed().as_secs_f64()
                );
            }
        }

        let l0 = storage.dir_runs.values().filter(|r| r.key.level == 0).count();
        assert!(l0 <= l0_max, "expected l0<={l0_max}, got {l0}");

        // Quick correctness smoke: at least one stream has readable tail bytes.
        let stream_id = "stream-0";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();
        let got = storage
            .read_tail(tenant_id, stream_type, stream_id, stream_hash, 16)
            .unwrap();
        assert!(!got.is_empty());

        // Checkpoint correctness sampling: install a cut (min_live_seq) and verify reads filter.
        let mut checkpoint_ok = true;
        let mut checkpoint_min_live_seq = 0u64;
        let events = storage
            .read_stream(tenant_id, stream_type, stream_id, stream_hash, 1, 0)
            .unwrap();
        let checkpoint_stream_len = events.len();
        if events.len() >= 4 {
            checkpoint_min_live_seq = events[events.len() / 2].seq;
            storage
                .update_stream_meta(stream_hash, checkpoint_min_live_seq, 0)
                .unwrap();
            storage.compact_directory_until_within_limits().unwrap();
            let after = storage
                .read_stream(tenant_id, stream_type, stream_id, stream_hash, 1, 0)
                .unwrap();
            checkpoint_ok = after.iter().all(|e| e.seq >= checkpoint_min_live_seq);
        }
        assert!(checkpoint_ok, "checkpoint sampling failed");
        assert_eq!(eq_mismatches, 0, "compaction equivalence mismatches");

        // Emit a stable JSON summary when run with `-- --nocapture` so soak workflows can archive it.
        eprintln!(
            "{}",
            serde_json::json!({
              "ok": true,
              "duration_secs": (start.elapsed().as_secs_f64() * 100.0).round() / 100.0,
              "events_appended": i,
              "streams": streams,
              "dir_l0_max_runs": l0_max,
              "dir_l0_runs_observed": l0,
              "compaction_events_seen": compaction_events_seen,
              "compaction_equivalence_checks": eq_checks,
              "compaction_equivalence_mismatches": eq_mismatches,
              "checkpoint_sampling_ok": checkpoint_ok,
              "checkpoint_sampling_min_live_seq": checkpoint_min_live_seq,
              "checkpoint_sampling_stream_events": checkpoint_stream_len,
            })
        );
    }

    #[test]
    fn tombstone_and_checkpoint_filter_reads_deterministically() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let opts = ShardStorageOptions {
            enable_directory_compaction: true,
            dir_l0_max_runs: 2,
            ..Default::default()
        };
        let (_dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        // 6 segments, 1 event each (seq 1..=6).
        for i in 0..6u32 {
            let eid = format!("e{i}");
            let payload = b"x";
            let events = [AppendEventInput {
                event_id: &eid,
                occurred_at: "2026-02-06T00:00:00Z",
                event_type: "t",
                content_type: "application/octet-stream",
                payload_bytes: payload,
            }];
            storage
                .append_batch(
                    stream_hash,
                    0,
                    tenant_id,
                    stream_type,
                    stream_id,
                    "2026-02-06T00:00:01Z",
                    &events,
                )
                .unwrap();
        }
        storage.compact_directory_until_within_limits().unwrap();

        // Tombstone hides seq < 5; checkpoint hides seq < 6; combined cut=6.
        storage.update_stream_meta(stream_hash, 6, 5).unwrap();
        storage.compact_directory_until_within_limits().unwrap();

        let got = storage
            .read_stream(tenant_id, stream_type, stream_id, stream_hash, 1, 0)
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].seq, 6);
    }

    #[test]
    fn tombstoned_stream_rejects_appends() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        storage.update_stream_meta(stream_hash, 0, 5).unwrap();

        let ev = AppendEventInput {
            event_id: "e1",
            occurred_at: "2026-02-06T00:00:00Z",
            event_type: "t",
            content_type: "application/octet-stream",
            payload_bytes: b"hello",
        };

        let err = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                std::slice::from_ref(&ev),
            )
            .unwrap_err();
        match err {
            StorageError::FailedPrecondition { code, .. } => {
                assert_eq!(code, "STREAM_TOMBSTONED");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn stream_meta_updates_are_monotonic() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        storage.update_stream_meta(stream_hash, 10, 20).unwrap();

        let err = storage.update_stream_meta(stream_hash, 9, 0).unwrap_err();
        assert!(matches!(
            err,
            StorageError::InvalidArgument { code, .. } if code == "CHECKPOINT_NON_MONOTONIC"
        ));

        let err = storage.update_stream_meta(stream_hash, 0, 19).unwrap_err();
        assert!(matches!(
            err,
            StorageError::InvalidArgument { code, .. } if code == "TOMBSTONE_NON_MONOTONIC"
        ));
    }

    #[test]
    fn append_batch_dedupes_within_batch() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let (dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        let payload = b"hello";
        let events = [
            AppendEventInput {
                event_id: "e1",
                occurred_at: "2026-02-06T00:00:00Z",
                event_type: "t",
                content_type: "application/octet-stream",
                payload_bytes: payload,
            },
            AppendEventInput {
                event_id: "e1",
                occurred_at: "2026-02-06T00:00:00Z",
                event_type: "t",
                content_type: "application/octet-stream",
                payload_bytes: payload,
            },
        ];

        let outcomes = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &events,
            )
            .unwrap();
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].status, AppendStatus::Appended);
        assert_eq!(outcomes[1].status, AppendStatus::DuplicateInBatch);
        assert_eq!(outcomes[0].seq, outcomes[1].seq);
        assert_eq!(outcomes[0].location, outcomes[1].location);

        assert_eq!(storage.segments_in_order.len(), 1);
        let seg = &storage.segments_in_order[0];
        let bytes = std::fs::read(storage.paths.shard_dir.join(&seg.relative_path)).unwrap();
        let (_h, _toc_h, entries, _f) = decode_segment_v1(&bytes).unwrap();
        assert_eq!(entries.len(), 1);

        drop(dir);
    }

    #[test]
    fn append_batch_with_stats_reports_stage_timings() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        let events = [AppendEventInput {
            event_id: "e1",
            occurred_at: "2026-02-06T00:00:00Z",
            event_type: "t",
            content_type: "application/octet-stream",
            payload_bytes: b"hello",
        }];

        let (outcomes, stats) = storage
            .append_batch_with_stats(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &events,
            )
            .unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].status, AppendStatus::Appended);

        assert!(stats.total_nanos > 0);
        assert!(stats.total_nanos >= stats.idempotency_check_nanos);
        assert!(stats.total_nanos >= stats.index_update_nanos);
        assert!(stats.total_nanos >= stats.io_write_nanos);
        assert!(stats.total_nanos >= stats.fence_wait_nanos);
        assert!(stats.total_nanos >= stats.fence_fsync_nanos);
        assert!(stats.total_nanos >= stats.fence_nanos);
        assert!(stats.fence_nanos >= stats.fence_wait_nanos.saturating_add(stats.fence_fsync_nanos));
        assert!(stats.io_write_nanos.saturating_add(stats.fence_nanos) > 0);
    }

    #[test]
    fn append_batch_with_stats_reports_write_confirmation_hash() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        let events = [
            AppendEventInput {
                event_id: "e1",
                occurred_at: "2026-02-06T00:00:00Z",
                event_type: "t",
                content_type: "application/octet-stream",
                payload_bytes: b"hello",
            },
            AppendEventInput {
                event_id: "e2",
                occurred_at: "2026-02-06T00:00:02Z",
                event_type: "t",
                content_type: "application/octet-stream",
                payload_bytes: b"world",
            },
        ];

        let (outcomes, stats) = storage
            .append_batch_with_stats(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:03Z",
                &events,
            )
            .unwrap();
        let confirmation = stats.write_confirmation.expect("write confirmation");
        let seal_receipt = stats.seal_receipt.expect("seal receipt material");

        let mut hasher = blake3::Hasher::new();
        for outcome in &outcomes {
            let loc = outcome.location.expect("appended frame location");
            let frame = storage
                .read_frame_bytes(loc.segment_seq, loc.offset)
                .expect("read stored frame bytes");
            hasher.update(blake3::hash(&frame).as_bytes());
        }

        assert_eq!(confirmation.commit_seq, outcomes.last().expect("outcome").seq);
        assert_eq!(
            confirmation.segment_id,
            outcomes
                .last()
                .and_then(|outcome| outcome.location.map(|loc| loc.segment_seq))
                .expect("segment id")
        );
        assert_eq!(confirmation.receipt_hash, *hasher.finalize().as_bytes());
        let seg = storage.segments_in_order.last().expect("sealed segment");
        assert_eq!(seal_receipt.segment_seq, seg.segment_seq);
        assert_eq!(seal_receipt.segment_hash, seg.segment_hash);
        assert_eq!(seal_receipt.previous_segment_seq, None);
        assert_eq!(seal_receipt.previous_segment_hash, None);
        assert_eq!(seal_receipt.frame_count, outcomes.len() as u64);
        assert_ne!(seal_receipt.material_hash(), [0u8; 32]);
    }

    #[test]
    fn append_batch_seal_receipt_links_previous_segment_hash() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());
        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        let (_, first_stats) = storage
            .append_batch_with_stats(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:00Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"hello",
                }],
            )
            .unwrap();
        let first = first_stats.seal_receipt.expect("first seal receipt");

        let (_, second_stats) = storage
            .append_batch_with_stats(
                stream_hash,
                2,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &[AppendEventInput {
                    event_id: "e2",
                    occurred_at: "2026-02-06T00:00:01Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"world",
                }],
            )
            .unwrap();
        let second = second_stats.seal_receipt.expect("second seal receipt");

        assert_eq!(second.previous_segment_seq, Some(first.segment_seq));
        assert_eq!(second.previous_segment_hash, Some(first.segment_hash));
        assert_ne!(second.material_hash(), first.material_hash());
    }

    #[test]
    fn load_manifest_segment_catalog_returns_sorted_segments() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());
        let tenant_id = "tenant-a";
        let stream_type = "answers";
        let stream_id = "stream-a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();
        let occurred_at = "2026-03-07T00:00:00Z";
        let events = [
            AppendEventInput {
                event_id: "evt-1",
                occurred_at,
                event_type: "evt",
                content_type: "application/json",
                payload_bytes: br#"{"n":1}"#,
            },
            AppendEventInput {
                event_id: "evt-2",
                occurred_at,
                event_type: "evt",
                content_type: "application/json",
                payload_bytes: br#"{"n":2}"#,
            },
        ];
        storage
            .append_batch(stream_hash, 0, tenant_id, stream_type, stream_id, occurred_at, &events)
            .expect("append batch");

        let catalog = load_manifest_segment_catalog(&storage.paths.shard_dir).expect("manifest catalog");
        assert_eq!(catalog.shard_id, 1);
        assert_eq!(catalog.epoch, 1);
        assert!(!catalog.segments.is_empty());
        assert!(catalog.manifest_end >= MANIFEST_HEADER_LEN as u64);
        assert!(catalog
            .segments
            .windows(2)
            .all(|window| window[0].segment_seq <= window[1].segment_seq));
    }

    #[test]
    fn duplicate_committed_returns_existing_seq_and_location() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        let ev = AppendEventInput {
            event_id: "e1",
            occurred_at: "2026-02-06T00:00:00Z",
            event_type: "t",
            content_type: "application/octet-stream",
            payload_bytes: b"hello",
        };

        let first = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                std::slice::from_ref(&ev),
            )
            .unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].status, AppendStatus::Appended);
        assert_eq!(storage.segments_in_order.len(), 1);

        let second = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:02Z",
                std::slice::from_ref(&ev),
            )
            .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].status, AppendStatus::DuplicateCommitted);
        assert_eq!(second[0].seq, first[0].seq);
        assert_eq!(second[0].location, first[0].location);
        assert_eq!(storage.segments_in_order.len(), 1);
    }

    #[test]
    fn hash_collision_does_not_cause_false_dedupe() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let opts = ShardStorageOptions {
            event_id_hash_prefix_len: 1,
            idem_hot_capacity_entries: 1024,
            ..Default::default()
        };
        let (_dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        // Find two different eventIds that collide on the first hash byte.
        let (a, b) = {
            let mut seen: HashMap<u8, String> = HashMap::new();
            let mut out: Option<(String, String)> = None;
            for i in 0..10_000u32 {
                let s = format!("ev-{i}");
                let h = blake3::hash(s.as_bytes());
                let k = h.as_bytes()[0];
                if let Some(prev) = seen.insert(k, s.clone()) {
                    out = Some((prev, s));
                    break;
                }
            }
            out.expect("expected to find a collision")
        };

        let ev_a = AppendEventInput {
            event_id: &a,
            occurred_at: "2026-02-06T00:00:00Z",
            event_type: "t",
            content_type: "application/octet-stream",
            payload_bytes: b"a",
        };
        let ev_b = AppendEventInput {
            event_id: &b,
            occurred_at: "2026-02-06T00:00:00Z",
            event_type: "t",
            content_type: "application/octet-stream",
            payload_bytes: b"b",
        };

        let r1 = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                std::slice::from_ref(&ev_a),
            )
            .unwrap();
        assert_eq!(r1[0].status, AppendStatus::Appended);

        let r2 = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:02Z",
                &[ev_b],
            )
            .unwrap();
        assert_eq!(r2[0].status, AppendStatus::Appended);
        assert_ne!(r2[0].seq, r1[0].seq);

        // Retry A must still be treated as committed duplicate.
        let r3 = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:03Z",
                &[ev_a],
            )
            .unwrap();
        assert_eq!(r3[0].status, AppendStatus::DuplicateCommitted);
        assert_eq!(r3[0].seq, r1[0].seq);
    }

    #[test]
    fn eviction_falls_back_to_cold_scan_for_correctness() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let opts = ShardStorageOptions {
            idem_hot_capacity_entries: 1,
            cold_scan_max_segments: 32,
            ..Default::default()
        };
        let (_dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        let ev_a = AppendEventInput {
            event_id: "a",
            occurred_at: "2026-02-06T00:00:00Z",
            event_type: "t",
            content_type: "application/octet-stream",
            payload_bytes: b"a",
        };
        let ev_b = AppendEventInput {
            event_id: "b",
            occurred_at: "2026-02-06T00:00:00Z",
            event_type: "t",
            content_type: "application/octet-stream",
            payload_bytes: b"b",
        };

        let r1 = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                std::slice::from_ref(&ev_a),
            )
            .unwrap();
        assert_eq!(r1[0].status, AppendStatus::Appended);
        assert_eq!(storage.segments_in_order.len(), 1);

        let _ = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:02Z",
                &[ev_b],
            )
            .unwrap();
        assert_eq!(storage.segments_in_order.len(), 2);

        // A was evicted from hot cache but must still dedupe via cold scan.
        let r3 = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:03Z",
                &[ev_a],
            )
            .unwrap();
        assert_eq!(r3[0].status, AppendStatus::DuplicateCommitted);
        assert_eq!(r3[0].seq, r1[0].seq);
        assert_eq!(storage.segments_in_order.len(), 2);
    }

    #[test]
    fn event_id_too_large_is_rejected_and_does_not_consume_seq() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let opts = ShardStorageOptions {
            max_event_id_bytes: 3,
            ..Default::default()
        };
        let (_dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        let oversize = AppendEventInput {
            event_id: "abcd",
            occurred_at: "2026-02-06T00:00:00Z",
            event_type: "t",
            content_type: "application/octet-stream",
            payload_bytes: b"x",
        };
        let r1 = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &[oversize],
            )
            .unwrap();
        assert_eq!(r1[0].status, AppendStatus::Rejected);
        assert_eq!(r1[0].seq, 0);
        assert_eq!(r1[0].error_code.as_deref(), Some("EVENT_ID_TOO_LARGE"));
        assert_eq!(storage.segments_in_order.len(), 0);

        let ok = AppendEventInput {
            event_id: "ok",
            occurred_at: "2026-02-06T00:00:00Z",
            event_type: "t",
            content_type: "application/octet-stream",
            payload_bytes: b"y",
        };
        let r2 = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:02Z",
                &[ok],
            )
            .unwrap();
        assert_eq!(r2[0].status, AppendStatus::Appended);
        assert_eq!(r2[0].seq, 1);
    }

    #[test]
    fn backpressure_max_events_rejects_entire_request() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let opts = ShardStorageOptions {
            max_events_per_batch: 1,
            ..Default::default()
        };
        let (_dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        let events = [
            AppendEventInput {
                event_id: "a",
                occurred_at: "2026-02-06T00:00:00Z",
                event_type: "t",
                content_type: "application/octet-stream",
                payload_bytes: b"a",
            },
            AppendEventInput {
                event_id: "b",
                occurred_at: "2026-02-06T00:00:00Z",
                event_type: "t",
                content_type: "application/octet-stream",
                payload_bytes: b"b",
            },
        ];

        let err = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &events,
            )
            .unwrap_err();
        match err {
            StorageError::ResourceExhausted { code, .. } => {
                assert_eq!(code, "BACKPRESSURE_MAX_EVENTS");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn crash_after_manifest_commit_is_idempotent_on_restart() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let opts = ShardStorageOptions {
            idem_hot_capacity_entries: 4,
            ..Default::default()
        };
        let (dir, mut storage) = open_test_storage(opts.clone());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        set_test_failpoint("after_manifest_commit");
        let err = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap_err();
        assert!(format!("{err}").contains("after_manifest_commit"));
        clear_test_failpoint();
        drop(storage);

        let mut reopened = ShardStorage::open(dir.path(), 1, 1, opts).unwrap();

        let retry = reopened
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:02Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap();
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].status, AppendStatus::DuplicateCommitted);
        assert_eq!(retry[0].seq, 1);
        assert!(retry[0].location.is_some());
    }

    #[test]
    fn crash_after_manifest_commit_keeps_replay_digest_stable_after_retry() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let opts = ShardStorageOptions {
            idem_hot_capacity_entries: 4,
            ..Default::default()
        };
        let (dir, mut storage) = open_test_storage(opts.clone());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        set_test_failpoint("after_manifest_commit");
        let err = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap_err();
        assert!(format!("{err}").contains("after_manifest_commit"));
        clear_test_failpoint();
        drop(storage);

        let mut reopened = ShardStorage::open(dir.path(), 1, 1, opts).unwrap();

        let (before_frames, before_end) = reopened.replay_from(None, 0).unwrap();
        assert_eq!(before_end, None);
        let (before_total, before_digest) = replay_digest(&before_frames);
        assert_eq!(before_total, 1);

        let retry = reopened
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:02Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap();
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].status, AppendStatus::DuplicateCommitted);

        let (after_frames, after_end) = reopened.replay_from(None, 0).unwrap();
        assert_eq!(after_end, None);
        let (after_total, after_digest) = replay_digest(&after_frames);
        assert_eq!(after_total, 1);
        assert_eq!(before_digest, after_digest);
    }

    #[test]
    fn crash_after_rename_before_manifest_quarantines_orphan_and_avoids_seq_reuse() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let opts = ShardStorageOptions::default();
        let (dir, mut storage) = open_test_storage(opts.clone());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        set_test_failpoint("after_rename_before_manifest");
        let err = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap_err();
        assert!(format!("{err}").contains("after_rename_before_manifest"));
        clear_test_failpoint();
        drop(storage);

        let mut reopened = ShardStorage::open(dir.path(), 1, 1, opts).unwrap();

        assert_eq!(reopened.segments_in_order.len(), 0);
        let out = reopened
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:02Z",
                &[AppendEventInput {
                    event_id: "e2",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"y",
                }],
            )
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].status, AppendStatus::Appended);
        assert_eq!(reopened.segments_in_order.len(), 1);
        assert_eq!(reopened.segments_in_order[0].segment_seq, 2);
    }

    #[test]
    fn commit_frame_roundtrip_and_crc_validation() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let frame = encode_commit_frame_v1(7, 42, 8192, 0xAABB_CCDD);
        let parsed = decode_commit_frame_v1(&frame).expect("commit frame decode");
        assert_eq!(parsed.commit_id, 7);
        assert_eq!(parsed.commit_seq, 42);
        assert_eq!(parsed.commit_offset, 8192);
        assert_eq!(parsed.crc32c_committed_region, 0xAABB_CCDD);

        let mut corrupted = frame;
        corrupted[16] ^= 0xFF; // mutate commit_seq field
        let err = decode_commit_frame_v1(&corrupted).expect_err("crc must fail");
        assert!(
            format!("{err}").contains("commit frame header crc mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn head_recovery_truncates_tail_to_last_commit_frame_boundary() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let opts = ShardStorageOptions {
            head_max_record_bytes: 1024 * 1024,
            ..Default::default()
        };
        let (dir, mut storage) = open_test_storage(opts.clone());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        let out = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].status, AppendStatus::Appended);

        let rel = storage.head.as_ref().expect("head exists").relative_path.clone();
        let head_path = storage.paths.shard_dir.join(rel);
        let committed_len = std::fs::metadata(&head_path).unwrap().len();
        {
            let mut f = OpenOptions::new().append(true).open(&head_path).unwrap();
            f.write_all(b"garbage-tail-without-commit-frame").unwrap();
            f.sync_all().unwrap();
        }
        let len_with_garbage = std::fs::metadata(&head_path).unwrap().len();
        assert!(len_with_garbage > committed_len);
        drop(storage);

        let reopened = ShardStorage::open(dir.path(), 1, 1, opts).unwrap();

        let len_recovered = std::fs::metadata(&head_path).unwrap().len();
        assert_eq!(len_recovered, committed_len);
        let tail = reopened
            .read_tail(tenant_id, stream_type, stream_id, stream_hash, 8)
            .unwrap();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].event_id, "e1");
    }

    #[test]
    fn crash_after_head_commit_fence_before_ack_is_idempotent_after_restart() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let opts = ShardStorageOptions {
            head_max_record_bytes: 1024 * 1024,
            idem_hot_capacity_entries: 4,
            ..Default::default()
        };
        let (dir, mut storage) = open_test_storage(opts.clone());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        set_test_failpoint("after_head_commit_fence_before_ack");
        let err = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap_err();
        assert!(format!("{err}").contains("after_head_commit_fence_before_ack"));
        clear_test_failpoint();
        drop(storage);

        let mut reopened = ShardStorage::open(dir.path(), 1, 1, opts).unwrap();

        let retry = reopened
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:02Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap();
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].status, AppendStatus::DuplicateCommitted);
        assert_eq!(retry[0].seq, 1);
        assert!(retry[0].location.is_some());
    }

    // ── Crash-recovery matrix completion ─────────────────────────────────────
    // ExecPlan crux-storage-fault-hardening-2026-06-11, M2. Together with the
    // existing crash_* tests this covers every injected failpoint:
    //   before seal        → after_seq_assignment        (new)
    //   mid-seal           → after_write_tmp             (new)
    //   sealed pre-manifest→ after_rename_before_manifest (existing)
    //   mid/post-manifest  → after_manifest_commit        (existing ×2)
    //   head pre-fence     → after_head_commit_frame_write_before_fence (new)
    //   head post-fence    → after_head_commit_fence_before_ack (existing)
    // All tests run against tempdirs only (open_test_storage), never real data dirs.

    /// Crash before any bytes hit disk (sequence numbers assigned in memory
    /// only). Recovery must show an empty shard; the retry is a fresh append
    /// (seq 1, Appended), and exactly one frame replays afterwards.
    #[test]
    fn crash_after_seq_assignment_persists_nothing_and_retry_is_fresh_append() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let opts = ShardStorageOptions {
            idem_hot_capacity_entries: 4,
            ..Default::default()
        };
        let (dir, mut storage) = open_test_storage(opts.clone());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        set_test_failpoint("after_seq_assignment");
        let err = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap_err();
        assert!(format!("{err}").contains("after_seq_assignment"));
        clear_test_failpoint();
        drop(storage);

        let mut reopened = ShardStorage::open(dir.path(), 1, 1, opts).unwrap();

        assert_eq!(reopened.segments_in_order.len(), 0);
        let (frames, _) = reopened.replay_from(None, 0).unwrap();
        let (total, _) = replay_digest(&frames);
        assert_eq!(total, 0, "nothing must replay after a pre-write crash");

        let retry = reopened
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:02Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap();
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].status, AppendStatus::Appended);
        assert_eq!(retry[0].seq, 1);

        let (frames, _) = reopened.replay_from(None, 0).unwrap();
        let (total, _) = replay_digest(&frames);
        assert_eq!(total, 1);
    }

    /// Crash mid-seal: the segment bytes were written to `tmp/` but never
    /// renamed into `segments/`. Recovery must not surface the partial file as
    /// a segment, must not lose the sequence space, and a retry must succeed
    /// with a stable replay digest.
    #[test]
    fn crash_after_write_tmp_ignores_partial_and_recovers_cleanly() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let opts = ShardStorageOptions {
            idem_hot_capacity_entries: 4,
            ..Default::default()
        };
        let (dir, mut storage) = open_test_storage(opts.clone());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        set_test_failpoint("after_write_tmp");
        let err = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap_err();
        assert!(format!("{err}").contains("after_write_tmp"));
        clear_test_failpoint();

        // The crash left a partial file in tmp/ and nothing in segments/.
        let tmp_partials: Vec<_> = std::fs::read_dir(&storage.paths.tmp_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(!tmp_partials.is_empty(), "expected a .partial leftover in tmp/");
        let sealed: Vec<_> = std::fs::read_dir(&storage.paths.segments_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(sealed.is_empty(), "no sealed segment may exist after a mid-seal crash");
        drop(storage);

        let mut reopened = ShardStorage::open(dir.path(), 1, 1, opts).unwrap();

        // The partial must not be loaded as a segment.
        assert_eq!(reopened.segments_in_order.len(), 0);
        let (frames, _) = reopened.replay_from(None, 0).unwrap();
        let (total, _) = replay_digest(&frames);
        assert_eq!(total, 0);

        let retry = reopened
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:02Z",
                &[AppendEventInput {
                    event_id: "e2",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"y",
                }],
            )
            .unwrap();
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].status, AppendStatus::Appended);
        assert_eq!(reopened.segments_in_order.len(), 1);

        // Replay digest stable across a further reopen (digest matrix column).
        let (frames, _) = reopened.replay_from(None, 0).unwrap();
        let (total_a, digest_a) = replay_digest(&frames);
        assert_eq!(total_a, 1);
        drop(reopened);
        let reopened_again = ShardStorage::open(
            dir.path(),
            1,
            1,
            ShardStorageOptions {
                idem_hot_capacity_entries: 4,
                ..Default::default()
            },
        )
        .unwrap();
        let (frames, _) = reopened_again.replay_from(None, 0).unwrap();
        let (total_b, digest_b) = replay_digest(&frames);
        assert_eq!(total_b, 1);
        assert_eq!(digest_a, digest_b);
    }

    /// Head-mode crash after the commit frame is written+synced but before the
    /// publish fence: the data is durable, the ack was lost. The retry must be
    /// recognised as DuplicateCommitted (no double-append).
    #[test]
    fn crash_after_head_commit_frame_write_before_fence_is_idempotent_after_restart() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let opts = ShardStorageOptions {
            head_max_record_bytes: 1024 * 1024,
            idem_hot_capacity_entries: 4,
            ..Default::default()
        };
        let (dir, mut storage) = open_test_storage(opts.clone());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        set_test_failpoint("after_head_commit_frame_write_before_fence");
        let err = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap_err();
        assert!(format!("{err}").contains("after_head_commit_frame_write_before_fence"));
        clear_test_failpoint();
        drop(storage);

        let mut reopened = ShardStorage::open(dir.path(), 1, 1, opts).unwrap();

        let retry = reopened
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:02Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap();
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].status, AppendStatus::DuplicateCommitted);
        assert_eq!(retry[0].seq, 1);
        assert!(retry[0].location.is_some());

        let tail = reopened
            .read_tail(tenant_id, stream_type, stream_id, stream_hash, 8)
            .unwrap();
        assert_eq!(tail.len(), 1, "exactly one durable copy of e1 after replayed ack");
        assert_eq!(tail[0].event_id, "e1");
    }

    #[test]
    fn read_tail_returns_last_n_across_segments() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        for i in 1..=5 {
            let event_id = format!("e{i}");
            let out = storage
                .append_batch(
                    stream_hash,
                    0,
                    tenant_id,
                    stream_type,
                    stream_id,
                    "2026-02-06T00:00:01Z",
                    std::slice::from_ref(&AppendEventInput {
                        event_id: &event_id,
                        occurred_at: "2026-02-06T00:00:00Z",
                        event_type: "t",
                        content_type: "application/octet-stream",
                        payload_bytes: b"x",
                    }),
                )
                .unwrap();
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].status, AppendStatus::Appended);
        }

        let tail = storage
            .read_tail(tenant_id, stream_type, stream_id, stream_hash, 3)
            .unwrap();
        assert_eq!(tail.len(), 3);
        assert_eq!(tail[0].seq, 3);
        assert_eq!(tail[1].seq, 4);
        assert_eq!(tail[2].seq, 5);
        assert_eq!(tail[0].event_id, "e3");
        assert_eq!(tail[1].event_id, "e4");
        assert_eq!(tail[2].event_id, "e5");
    }

    #[test]
    fn read_stream_range_respects_from_seq_and_limit() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        for i in 1..=5 {
            let event_id = format!("e{i}");
            let _ = storage
                .append_batch(
                    stream_hash,
                    0,
                    tenant_id,
                    stream_type,
                    stream_id,
                    "2026-02-06T00:00:01Z",
                    std::slice::from_ref(&AppendEventInput {
                        event_id: &event_id,
                        occurred_at: "2026-02-06T00:00:00Z",
                        event_type: "t",
                        content_type: "application/octet-stream",
                        payload_bytes: b"x",
                    }),
                )
                .unwrap();
        }

        let got = storage
            .read_stream(tenant_id, stream_type, stream_id, stream_hash, 4, 2)
            .unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].seq, 4);
        assert_eq!(got[1].seq, 5);
        assert_eq!(got[0].event_id, "e4");
        assert_eq!(got[1].event_id, "e5");
    }

    #[test]
    fn tail_locator_helpers_truncate_group_and_fallback() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let stream_hash = 0x42;
        let first: Vec<_> = (1..=40)
            .map(|seq| toc_entry(stream_hash, seq, 0, seq as u32, 16))
            .collect();
        let second: Vec<_> = (41..=66)
            .map(|seq| toc_entry(stream_hash, seq, 1, seq as u32, 16))
            .collect();

        storage.update_tail_locator_for_stream_entries(stream_hash, 10, &first);
        storage.update_tail_locator_for_stream_entries(stream_hash, 11, &second);

        let locator = storage.tail_locator_by_stream.get(&stream_hash).expect("tail locator");
        assert_eq!(locator.entries_asc.len(), STREAM_TAIL_LOCATOR_MAX_EVENTS);
        assert_eq!(locator.entries_asc.first().expect("oldest locator entry").entry.seq, 3);

        let pointer = storage.tail_pointer_by_stream.get(&stream_hash).expect("tail pointer");
        assert_eq!(pointer.latest_segment_seq, 11);
        assert_eq!(pointer.latest_seq, 66);
        assert_eq!(pointer.grouped_desc.len(), 2);
        assert_eq!(pointer.grouped_desc[0].segment_seq, 11);
        assert_eq!(pointer.grouped_desc[0].entries_desc[0].seq, 66);

        let fast_entries = storage.locator_tail_entries_desc(stream_hash, 60, 4);
        assert_eq!(
            fast_entries.iter().map(|entry| entry.entry.seq).collect::<Vec<_>>(),
            vec![66, 65, 64, 63]
        );

        let (fast_groups, fast_full) = storage.locator_tail_segments_desc(stream_hash, 60, 4);
        assert!(fast_full);
        assert_eq!(fast_groups.len(), 1);
        assert_eq!(fast_groups[0].0, 11);
        assert_eq!(
            fast_groups[0].1.iter().map(|entry| entry.seq).collect::<Vec<_>>(),
            vec![66, 65, 64, 63]
        );

        storage.tail_pointer_by_stream.clear();
        let fallback_entries = storage.locator_tail_entries_desc(stream_hash, 65, 3);
        assert_eq!(
            fallback_entries
                .iter()
                .map(|entry| (entry.segment_seq, entry.entry.seq))
                .collect::<Vec<_>>(),
            vec![(11, 66), (11, 65)]
        );

        let (fallback_groups, fallback_full) = storage.locator_tail_segments_desc(stream_hash, 65, 3);
        assert!(!fallback_full);
        assert_eq!(fallback_groups.len(), 1);
        assert_eq!(fallback_groups[0].0, 11);
        assert_eq!(
            fallback_groups[0].1.iter().map(|entry| entry.seq).collect::<Vec<_>>(),
            vec![66, 65]
        );

        assert!(storage.locator_tail_entries_desc(stream_hash, 0, 0).is_empty());
        let (no_groups, no_full) = storage.locator_tail_segments_desc(stream_hash, 0, 0);
        assert!(no_groups.is_empty());
        assert!(!no_full);
    }

    #[test]
    fn replay_from_cursor_continues_deterministically() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        for i in 1..=3 {
            let event_id = format!("e{i}");
            let _ = storage
                .append_batch(
                    stream_hash,
                    0,
                    tenant_id,
                    stream_type,
                    stream_id,
                    "2026-02-06T00:00:01Z",
                    std::slice::from_ref(&AppendEventInput {
                        event_id: &event_id,
                        occurred_at: "2026-02-06T00:00:00Z",
                        event_type: "t",
                        content_type: "application/octet-stream",
                        payload_bytes: b"x",
                    }),
                )
                .unwrap();
        }

        let (all, end) = storage.replay_from(None, 0).unwrap();
        assert_eq!(end, None);
        assert_eq!(all.len(), 3);

        let (part, cursor) = storage.replay_from(None, 1).unwrap();
        assert_eq!(part.len(), 1);
        let cursor = cursor.expect("cursor after partial replay");
        let (rest, end2) = storage.replay_from(Some(cursor), 0).unwrap();
        assert_eq!(end2, None);

        let mut combined: Vec<(FrameLocation, Vec<u8>)> = Vec::new();
        combined.extend_from_slice(&part);
        combined.extend_from_slice(&rest);

        assert_eq!(combined.len(), all.len());
        for (a, b) in combined.iter().zip(all.iter()) {
            assert_eq!(a.0, b.0);
            assert_eq!(a.1, b.1);
        }
    }

    #[test]
    fn head_segment_serves_reads_before_seal() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let opts = ShardStorageOptions {
            head_max_record_bytes: 1024 * 1024, // large enough to avoid sealing during test
            ..Default::default()
        };
        let (_dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        let mut locs: Vec<FrameLocation> = Vec::new();
        for i in 1..=5 {
            let event_id = format!("e{i}");
            let out = storage
                .append_batch(
                    stream_hash,
                    0,
                    tenant_id,
                    stream_type,
                    stream_id,
                    "2026-02-06T00:00:01Z",
                    std::slice::from_ref(&AppendEventInput {
                        event_id: &event_id,
                        occurred_at: "2026-02-06T00:00:00Z",
                        event_type: "t",
                        content_type: "application/octet-stream",
                        payload_bytes: b"x",
                    }),
                )
                .unwrap();
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].status, AppendStatus::Appended);
            locs.push(out[0].location.expect("location"));
        }

        // Head mode should avoid sealing a segment per append.
        assert_eq!(storage.segments_in_order.len(), 0);
        assert!(storage.head.is_some());

        // Locations should all refer to the same head segment seq.
        for w in locs.windows(2) {
            assert_eq!(w[0].segment_seq, w[1].segment_seq);
        }

        // Tail and range must include head bytes.
        let tail = storage
            .read_tail(tenant_id, stream_type, stream_id, stream_hash, 3)
            .unwrap();
        assert_eq!(tail.len(), 3);
        assert_eq!(tail[0].seq, 3);
        assert_eq!(tail[1].seq, 4);
        assert_eq!(tail[2].seq, 5);

        let got = storage
            .read_stream(tenant_id, stream_type, stream_id, stream_hash, 4, 2)
            .unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].seq, 4);
        assert_eq!(got[1].seq, 5);

        // replay_from must include head frames.
        let (frames, end) = storage.replay_from(None, 0).unwrap();
        assert_eq!(end, None);
        assert_eq!(frames.len(), 5);

        // read_frame_bytes must work against head locations.
        let frame = storage.read_frame_bytes(locs[0].segment_seq, locs[0].offset).unwrap();
        let _ = decode_frame_v1(&frame).unwrap();
    }

    #[test]
    fn read_frame_bytes_batch_supports_mixed_sealed_and_head_locations() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let opts = ShardStorageOptions {
            head_max_record_bytes: 1024 * 1024,
            ..Default::default()
        };
        let (_dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        for i in 1..=2 {
            let event_id = format!("sealed-{i}");
            storage
                .append_batch(
                    stream_hash,
                    0,
                    tenant_id,
                    stream_type,
                    stream_id,
                    "2026-02-06T00:00:01Z",
                    std::slice::from_ref(&AppendEventInput {
                        event_id: &event_id,
                        occurred_at: "2026-02-06T00:00:00Z",
                        event_type: "t",
                        content_type: "application/octet-stream",
                        payload_bytes: b"sealed",
                    }),
                )
                .unwrap();
        }
        storage.force_seal_head().unwrap();
        let sealed_locations: Vec<_> = storage
            .read_stream(tenant_id, stream_type, stream_id, stream_hash, 1, 2)
            .expect("sealed stream read")
            .into_iter()
            .map(|event| event.location)
            .collect();
        assert_eq!(sealed_locations.len(), 2);

        let mut head_locations = Vec::new();
        for i in 1..=2 {
            let event_id = format!("head-{i}");
            let out = storage
                .append_batch(
                    stream_hash,
                    0,
                    tenant_id,
                    stream_type,
                    stream_id,
                    "2026-02-06T00:00:02Z",
                    std::slice::from_ref(&AppendEventInput {
                        event_id: &event_id,
                        occurred_at: "2026-02-06T00:00:00Z",
                        event_type: "t",
                        content_type: "application/octet-stream",
                        payload_bytes: b"head",
                    }),
                )
                .unwrap();
            head_locations.push(out[0].location.expect("head location"));
        }

        let mut locations = Vec::new();
        locations.extend_from_slice(&sealed_locations);
        locations.extend_from_slice(&head_locations);

        let packed = storage.read_frame_bytes_batch_packed(&locations).expect("packed batch");
        assert_eq!(packed.frame_offsets.len(), 4);
        assert_eq!(packed.frame_lens.len(), 4);
        assert_eq!(
            packed.frame_bytes,
            packed.frame_lens.iter().map(|len| *len as u64).sum::<u64>()
        );
        assert!(!packed.frames_blob.is_empty());

        let frames = storage.read_frame_bytes_batch(&locations).expect("batch frames");
        assert_eq!(frames.len(), 4);
        for (location, frame) in locations.iter().zip(frames.iter()) {
            assert_eq!(
                frame,
                &storage
                    .read_frame_bytes(location.segment_seq, location.offset)
                    .expect("single frame")
            );
            let _ = decode_frame_v1(frame).expect("decode frame");
        }
    }

    #[test]
    fn read_frame_bytes_batch_packed_empty_returns_empty_payload() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, storage) = open_test_storage(ShardStorageOptions::default());

        let packed = storage.read_frame_bytes_batch_packed(&[]).expect("empty packed batch");
        assert!(packed.frames_blob.is_empty());
        assert!(packed.frame_offsets.is_empty());
        assert!(packed.frame_lens.is_empty());
        assert_eq!(packed.frame_bytes, 0);
    }

    #[test]
    fn head_segment_is_sealed_on_restart_when_disabled() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let opts = ShardStorageOptions {
            head_max_record_bytes: 1024 * 1024,
            ..Default::default()
        };
        let (dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        let _ = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap();
        drop(storage);

        // Reopen with head disabled; startup should seal any head file.

        let reopened = ShardStorage::open(dir.path(), 1, 1, ShardStorageOptions::default()).unwrap();

        assert_eq!(reopened.segments_in_order.len(), 1);
        assert!(reopened.head.is_none());
        let tail = reopened
            .read_tail(tenant_id, stream_type, stream_id, stream_hash, 1)
            .unwrap();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].event_id, "e1");

        drop(dir);
    }

    #[test]
    fn read_blocks_supports_lz4_codec() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("block.bin");

        let uncompressed = b"hello world hello world hello world";
        let compressed = lz4_flex::block::compress(uncompressed);

        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        f.write_all(&compressed).unwrap();
        f.sync_all().unwrap();

        let meta = BlockMetaV1 {
            block_id: 0,
            codec: 1,
            file_offset: 0,
            compressed_len: compressed.len() as u32,
            physical_len: compressed.len() as u32,
            uncompressed_len: uncompressed.len() as u32,
            crc32c: crc32c::crc32c(uncompressed),
            bloom: [0u8; corecrux_segment::BLOOM_BYTES_PER_BLOCK_V1],
        };

        let blocks = read_blocks_cpu(&f, std::slice::from_ref(&meta), &[0]).unwrap();
        let got = blocks[0].as_ref().unwrap();
        assert_eq!(got, uncompressed);
    }

    #[test]
    fn sealed_segments_with_lz4_blocks_support_tail_and_range_reads() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let opts = ShardStorageOptions {
            record_block_codec: corecrux_segment::RECORD_BLOCK_CODEC_LZ4_V1,
            ..Default::default()
        };
        let (_dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        for i in 1..=5 {
            let event_id = format!("e{i}");
            let out = storage
                .append_batch(
                    stream_hash,
                    0,
                    tenant_id,
                    stream_type,
                    stream_id,
                    "2026-02-06T00:00:01Z",
                    std::slice::from_ref(&AppendEventInput {
                        event_id: &event_id,
                        occurred_at: "2026-02-06T00:00:00Z",
                        event_type: "t",
                        content_type: "application/octet-stream",
                        payload_bytes: b"x",
                    }),
                )
                .unwrap();
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].status, AppendStatus::Appended);
        }

        // Assert codec=1 was actually used for sealed blocks.
        for ti in storage.segment_trailers_by_seq.values() {
            assert!(!ti.blocks.is_empty());
            for b in &ti.blocks {
                assert_eq!(b.codec, corecrux_segment::RECORD_BLOCK_CODEC_LZ4_V1);
            }
        }

        let tail = storage
            .read_tail(tenant_id, stream_type, stream_id, stream_hash, 3)
            .unwrap();
        assert_eq!(tail.len(), 3);
        assert_eq!(tail[0].seq, 3);
        assert_eq!(tail[1].seq, 4);
        assert_eq!(tail[2].seq, 5);

        let got = storage
            .read_stream(tenant_id, stream_type, stream_id, stream_hash, 4, 2)
            .unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].seq, 4);
        assert_eq!(got[1].seq, 5);

        let (frames, end) = storage.replay_from(None, 0).unwrap();
        assert_eq!(end, None);
        assert_eq!(frames.len(), 5);
        for (_loc, bytes) in frames {
            let _ = decode_frame_v1(&bytes).unwrap();
        }
    }

    fn repo_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repo root")
    }

    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    struct ExpectedReplayDigest {
        total_frames: u64,
        digest_blake3: String,
    }

    fn replay_digest(frames: &ReplayFrames) -> (u64, String) {
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

    #[test]
    fn replay_golden_segment_fixture_digest_matches_expected() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let fixture_dir = repo_root().join("tests/fixtures_segments/minimal");
        let fixture_seg = fixture_dir.join("minimal.ccxseg");
        let expected_path = fixture_dir.join("expected_replay_digest.json");

        let seg_bytes = std::fs::read(&fixture_seg).expect("read fixture segment");
        let (_h, _toc_h, _entries, footer) = corecrux_segment::decode_segment_v1(&seg_bytes).expect("decode segment");

        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();

        let shard_id = footer.shard_id;
        let epoch = footer.epoch;
        let paths = ShardPaths::for_root(root, shard_id);
        std::fs::create_dir_all(&paths.segments_dir).expect("create segments dir");

        let rel = "segments/minimal.ccxseg";
        let dst = paths.shard_dir.join(rel);
        std::fs::copy(&fixture_seg, &dst).expect("copy fixture segment");

        // Write MANIFEST referencing the fixture segment (Phase 2/3 layout).
        let mut mf = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&paths.manifest_path)
            .expect("create MANIFEST");
        let hdr = encode_manifest_header_v1(shard_id, epoch, 123).expect("manifest header");
        mf.write_all(&hdr).expect("write manifest header");

        let seg_meta = SegmentMeta {
            level: 0,
            shard_id,
            epoch,
            segment_seq: footer.segment_seq,
            segment_id: footer.segment_id,
            relative_path: rel.to_string(),
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
        let rec = encode_manifest_add_segment_v1(&seg_meta).expect("encode add segment");
        let framed = frame_manifest_record(&rec);
        mf.write_all(&framed).expect("write manifest record");
        mf.sync_all().expect("sync manifest");

        // Now open storage and replay on the same path (GPU-first in CUDA builds).

        let storage = ShardStorage::open(root, shard_id, epoch, ShardStorageOptions::default()).expect("open storage");

        let (frames, end) = storage.replay_from(None, 0).expect("replay fixture");
        assert_eq!(end, None);
        let (total_frames, digest_blake3) = replay_digest(&frames);

        let expected_str = match std::fs::read_to_string(&expected_path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let json = serde_json::to_string_pretty(&ExpectedReplayDigest {
                    total_frames,
                    digest_blake3: digest_blake3.clone(),
                })
                .expect("serialize expected digest");
                panic!(
                    "expected digest missing at {}. Create it with:\n{}",
                    expected_path.display(),
                    json
                );
            }
            Err(e) => panic!("read expected digest: {e}"),
        };
        let expected: ExpectedReplayDigest = serde_json::from_str(&expected_str).expect("parse expected digest");

        assert_eq!(total_frames, expected.total_frames);
        assert_eq!(digest_blake3, expected.digest_blake3);
    }

    #[test]
    fn integrity_scan_golden_segment_fixture_matches_expected_frame_count() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let fixture_dir = repo_root().join("tests/fixtures_segments/minimal");
        let fixture_seg = fixture_dir.join("minimal.ccxseg");
        let expected_path = fixture_dir.join("expected_replay_digest.json");

        let seg_bytes = std::fs::read(&fixture_seg).expect("read fixture segment");
        let (_h, _toc_h, _entries, footer) = corecrux_segment::decode_segment_v1(&seg_bytes).expect("decode segment");

        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();

        let shard_id = footer.shard_id;
        let epoch = footer.epoch;
        let paths = ShardPaths::for_root(root, shard_id);
        std::fs::create_dir_all(&paths.segments_dir).expect("create segments dir");

        let rel = "segments/minimal.ccxseg";
        let dst = paths.shard_dir.join(rel);
        std::fs::copy(&fixture_seg, &dst).expect("copy fixture segment");

        // Write MANIFEST referencing the fixture segment (Phase 2/3 layout).
        let mut mf = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&paths.manifest_path)
            .expect("create MANIFEST");
        let hdr = encode_manifest_header_v1(shard_id, epoch, 123).expect("manifest header");
        mf.write_all(&hdr).expect("write manifest header");

        let seg_meta = SegmentMeta {
            level: 0,
            shard_id,
            epoch,
            segment_seq: footer.segment_seq,
            segment_id: footer.segment_id,
            relative_path: rel.to_string(),
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
        let rec = encode_manifest_add_segment_v1(&seg_meta).expect("encode add segment");
        let framed = frame_manifest_record(&rec);
        mf.write_all(&framed).expect("write manifest record");
        mf.sync_all().expect("sync manifest");

        let storage = ShardStorage::open(root, shard_id, epoch, ShardStorageOptions::default()).expect("open storage");

        let stats = storage
            .integrity_scan_stats_all(8 * 1024 * 1024)
            .expect("integrity scan");

        let expected_str = std::fs::read_to_string(&expected_path).expect("read expected digest");
        let expected: ExpectedReplayDigest = serde_json::from_str(&expected_str).expect("parse expected digest");

        assert_eq!(stats.total_frames, expected.total_frames);
    }

    #[test]
    fn replay_and_integrity_scan_reject_zero_budget() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, storage) = open_test_storage(ShardStorageOptions::default());

        let replay_err = storage
            .replay_scan_stats_all(0)
            .expect_err("zero replay budget should fail");
        match replay_err {
            StorageError::InvalidArgument { code, .. } => assert_eq!(code, "BUDGET_BYTES_ZERO"),
            other => panic!("unexpected error: {other}"),
        }

        let integrity_err = storage
            .integrity_scan_stats_all(0)
            .expect_err("zero integrity budget should fail");
        match integrity_err {
            StorageError::InvalidArgument { code, .. } => assert_eq!(code, "BUDGET_BYTES_ZERO"),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn replay_scan_stats_counts_sealed_and_head_segments() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let opts = ShardStorageOptions {
            head_max_record_bytes: 1024 * 1024,
            ..Default::default()
        };
        let (_dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "scan";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        for i in 1..=2 {
            let event_id = format!("sealed-{i}");
            storage
                .append_batch(
                    stream_hash,
                    0,
                    tenant_id,
                    stream_type,
                    stream_id,
                    "2026-02-06T00:00:01Z",
                    std::slice::from_ref(&AppendEventInput {
                        event_id: &event_id,
                        occurred_at: "2026-02-06T00:00:00Z",
                        event_type: "t",
                        content_type: "application/octet-stream",
                        payload_bytes: b"x",
                    }),
                )
                .unwrap();
        }
        storage.force_seal_head().unwrap();

        for i in 1..=2 {
            let event_id = format!("head-{i}");
            storage
                .append_batch(
                    stream_hash,
                    0,
                    tenant_id,
                    stream_type,
                    stream_id,
                    "2026-02-06T00:00:02Z",
                    std::slice::from_ref(&AppendEventInput {
                        event_id: &event_id,
                        occurred_at: "2026-02-06T00:00:00Z",
                        event_type: "t",
                        content_type: "application/octet-stream",
                        payload_bytes: b"x",
                    }),
                )
                .unwrap();
        }

        let stats = storage.replay_scan_stats_all(1).expect("replay scan");
        assert_eq!(stats.total_segments, 2);
        assert_eq!(stats.total_frames, 4);
        assert!(stats.total_compressed_bytes > 0);
        assert!(stats.total_uncompressed_bytes > 0);
    }

    #[test]
    fn replay_and_integrity_scan_reject_missing_trailer_index() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "missing-trailer";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap();

        storage.segment_trailers_by_seq.clear();

        let replay_err = storage
            .replay_scan_stats_all(1024)
            .expect_err("missing trailer should fail replay scan");
        match replay_err {
            StorageError::ManifestRecordInvalid { msg } => {
                assert!(msg.contains("missing trailer index for sealed segment"));
            }
            other => panic!("unexpected error: {other}"),
        }

        let integrity_err = storage
            .integrity_scan_stats_all(1024)
            .expect_err("missing trailer should fail integrity scan");
        match integrity_err {
            StorageError::ManifestRecordInvalid { msg } => {
                assert!(msg.contains("missing trailer index for sealed segment"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn integrity_scan_detects_sealed_and_head_frame_count_mismatches() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, mut sealed_storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "t1";
        let stream_type = "s";
        let sealed_stream_id = "sealed-mismatch";
        let sealed_stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, sealed_stream_id).unwrap();

        sealed_storage
            .append_batch(
                sealed_stream_hash,
                0,
                tenant_id,
                stream_type,
                sealed_stream_id,
                "2026-02-06T00:00:01Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap();
        sealed_storage.segments_in_order[0].toc_entry_count += 1;

        let sealed_err = sealed_storage
            .integrity_scan_stats_all(1)
            .expect_err("sealed mismatch should fail");
        match sealed_err {
            StorageError::ManifestRecordInvalid { msg } => {
                assert!(msg.contains("integrity scan frame count mismatch for segment_seq"));
            }
            other => panic!("unexpected error: {other}"),
        }

        let opts = ShardStorageOptions {
            head_max_record_bytes: 1024 * 1024,
            ..Default::default()
        };
        let (_dir2, mut head_storage) = open_test_storage(opts);
        let head_stream_id = "head-mismatch";
        let head_stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, head_stream_id).unwrap();
        for i in 1..=2 {
            let event_id = format!("e{i}");
            head_storage
                .append_batch(
                    head_stream_hash,
                    0,
                    tenant_id,
                    stream_type,
                    head_stream_id,
                    "2026-02-06T00:00:01Z",
                    std::slice::from_ref(&AppendEventInput {
                        event_id: &event_id,
                        occurred_at: "2026-02-06T00:00:00Z",
                        event_type: "t",
                        content_type: "application/octet-stream",
                        payload_bytes: b"x",
                    }),
                )
                .unwrap();
        }
        head_storage
            .head
            .as_mut()
            .expect("head segment")
            .frames
            .pop()
            .expect("remove one head frame");

        let head_err = head_storage
            .integrity_scan_stats_all(1)
            .expect_err("head mismatch should fail");
        match head_err {
            StorageError::ManifestRecordInvalid { msg } => {
                assert!(msg.contains("integrity scan frame count mismatch for head segment_seq"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn tail_and_range_match_cpu_reference_scan_on_interleaved_segments() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let shard_id = 1u32;
        let epoch = 1u64;
        let paths = ShardPaths::for_root(root, shard_id);
        std::fs::create_dir_all(&paths.segments_dir).unwrap();

        let tenant_id = "t1";
        let stream_type = "s";
        let occurred_at = "2026-02-06T00:00:00Z";
        let ingested_at = "2026-02-06T00:00:01Z";
        let event_type = "t";
        let content_type = "application/octet-stream";

        let streams = ["a", "b", "c"];
        let mut stream_hashes: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
        for s in &streams {
            let h = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, s).unwrap();
            stream_hashes.insert(s, h);
        }

        #[allow(clippy::too_many_arguments)]
        fn build_segment_for_events(
            shard_id: u32,
            epoch: u64,
            segment_seq: u64,
            record_block_codec: u32,
            tenant_id: &str,
            stream_type: &str,
            occurred_at: &str,
            ingested_at: &str,
            event_type: &str,
            content_type: &str,
            events: &[(&str, u64, &str, &'static [u8])], // (stream_id, seq, event_id, payload)
        ) -> corecrux_segment::SegmentBuildOutput {
            use corecrux_frame::{
                canonical_header_bytes_v1, compute_header_hash, compute_payload_hash, CanonicalHeaderV1,
            };

            let segment_id = deterministic_segment_id(epoch, segment_seq);
            let created_at = 100 + segment_seq;
            let sealed_at = 200 + segment_seq;

            let n = events.len();
            let mut stream_hashes: Vec<u64> = Vec::with_capacity(n);
            let mut seqs: Vec<u64> = Vec::with_capacity(n);
            let mut event_ids: Vec<String> = Vec::with_capacity(n);
            let mut payload_hashes: Vec<[u8; 32]> = Vec::with_capacity(n);
            let mut header_hashes: Vec<[u8; 32]> = Vec::with_capacity(n);
            let mut payload_bufs: Vec<Vec<u8>> = Vec::with_capacity(n);
            let mut header_bufs: Vec<Vec<u8>> = Vec::with_capacity(n);

            for (stream_id, seq, event_id, payload) in events {
                let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();
                stream_hashes.push(stream_hash);
                seqs.push(*seq);
                event_ids.push((*event_id).to_string());
                payload_bufs.push(payload.to_vec());
                let payload_hash = compute_payload_hash(payload_bufs.last().unwrap().as_slice());

                let canonical = CanonicalHeaderV1 {
                    tenant_id: tenant_id.to_string(),
                    stream_id: (*stream_id).to_string(),
                    stream_type: stream_type.to_string(),
                    seq: *seq,
                    event_id: event_ids.last().unwrap().clone(),
                    occurred_at: occurred_at.to_string(),
                    ingested_at: ingested_at.to_string(),
                    event_type: event_type.to_string(),
                    content_type: content_type.to_string(),
                    payload_len: payload.len() as u32,
                    payload_hash,
                };
                let canonical_bytes = canonical_header_bytes_v1(&canonical);
                let header_hash = compute_header_hash(&canonical_bytes);

                let mut hb = Vec::with_capacity(canonical_bytes.len() + 32);
                hb.extend_from_slice(&canonical_bytes);
                hb.extend_from_slice(&header_hash);
                header_bufs.push(hb);

                payload_hashes.push(payload_hash);
                header_hashes.push(header_hash);
            }

            // Build FrameInput after buffers are stable (avoids borrow/realloc hazards).
            let mut frames: Vec<corecrux_segment::FrameInput<'_>> = Vec::with_capacity(n);
            for i in 0..n {
                frames.push(corecrux_segment::FrameInput {
                    stream_hash: stream_hashes[i],
                    seq: seqs[i],
                    event_id: event_ids[i].as_str(),
                    header_hash: header_hashes[i],
                    payload_hash: payload_hashes[i],
                    header_bytes: header_bufs[i].as_slice(),
                    payload_bytes: payload_bufs[i].as_slice(),
                });
            }

            corecrux_segment::build_segment_v1_with_block_codec(
                shard_id,
                epoch,
                segment_seq,
                segment_id,
                created_at,
                sealed_at,
                record_block_codec,
                &frames,
            )
            .unwrap()
        }

        // Two segments with three interleaved streams.
        let seg1 = build_segment_for_events(
            shard_id,
            epoch,
            1,
            corecrux_segment::RECORD_BLOCK_CODEC_LZ4_V1,
            tenant_id,
            stream_type,
            occurred_at,
            ingested_at,
            event_type,
            content_type,
            &[
                ("a", 1, "a1", b"x"),
                ("b", 1, "b1", b"y"),
                ("a", 2, "a2", b"z"),
                ("c", 1, "c1", b"q"),
                ("b", 2, "b2", b"w"),
            ],
        );
        let seg2 = build_segment_for_events(
            shard_id,
            epoch,
            2,
            corecrux_segment::RECORD_BLOCK_CODEC_LZ4_V1,
            tenant_id,
            stream_type,
            occurred_at,
            ingested_at,
            event_type,
            content_type,
            &[
                ("a", 3, "a3", b"x"),
                ("b", 3, "b3", b"y"),
                ("c", 2, "c2", b"z"),
                ("c", 3, "c3", b"q"),
                ("a", 4, "a4", b"w"),
            ],
        );

        let seg_metas = [(1u64, seg1.footer, seg1.bytes), (2u64, seg2.footer, seg2.bytes)];

        let mut manifest = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&paths.manifest_path)
            .unwrap();
        let hdr = encode_manifest_header_v1(shard_id, epoch, 123).unwrap();
        manifest.write_all(&hdr).unwrap();

        let mut metas: Vec<SegmentMeta> = Vec::new();
        for (segment_seq, footer, bytes) in seg_metas {
            let segment_id = footer.segment_id;
            let rel = format!("segments/seg-{segment_seq:020}-{}.ccxseg", hex16(&segment_id.0));
            let path = paths.shard_dir.join(&rel);
            std::fs::write(&path, &bytes).unwrap();

            let meta = SegmentMeta {
                level: 0,
                shard_id,
                epoch,
                segment_seq,
                segment_id,
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
            let rec = encode_manifest_add_segment_v1(&meta).unwrap();
            let framed = frame_manifest_record(&rec);
            manifest.write_all(&framed).unwrap();
            metas.push(meta);
        }
        manifest.sync_all().unwrap();

        // Open storage (GPU-first in CUDA builds).
        let storage = ShardStorage::open(root, shard_id, epoch, ShardStorageOptions::default()).unwrap();

        // CPU reference scan of the on-disk bytes (ignores directory + TOC sorted index).
        let mut scanned: Vec<(u64, StoredEvent)> = Vec::new();
        for seg in &metas {
            let seg_path = paths.shard_dir.join(&seg.relative_path);
            let bytes = std::fs::read(&seg_path).unwrap();
            let (_h, toc_h, _entries, footer) = corecrux_segment::decode_segment_v1(&bytes).unwrap();
            let toc_off = footer.toc_offset as usize;
            let toc_len = footer.toc_len as usize;
            let toc_area = &bytes[toc_off..toc_off + toc_len];
            let ti = corecrux_segment::decode_trailer_index_v1(toc_area, &toc_h)
                .unwrap()
                .expect("trailer index");
            let block_starts = block_logical_starts(&ti.blocks).unwrap();

            // Decompress all blocks once on CPU.
            let mut blocks_uncompressed: Vec<Vec<u8>> = vec![Vec::new(); ti.blocks.len()];
            for b in &ti.blocks {
                let off = b.file_offset as usize;
                let len = b.compressed_len as usize;
                let end = off + len;
                let compressed = &bytes[off..end];
                let mut out = match b.codec {
                    corecrux_segment::RECORD_BLOCK_CODEC_NONE_V1 => {
                        assert_eq!(b.compressed_len, b.uncompressed_len);
                        compressed.to_vec()
                    }
                    corecrux_segment::RECORD_BLOCK_CODEC_LZ4_V1 => {
                        let want = b.uncompressed_len as usize;
                        let out = lz4_flex::block::decompress(compressed, want).unwrap();
                        assert_eq!(out.len(), want);
                        out
                    }
                    other => panic!("unsupported codec {other} in fixture"),
                };
                let actual_crc = crc32c::crc32c(&out);
                assert_eq!(actual_crc, b.crc32c);
                blocks_uncompressed[b.block_id as usize].append(&mut out);
            }

            for e in &ti.toc_by_offset {
                let bid = e.block_id as usize;
                let buf = &blocks_uncompressed[bid];
                let start = e.in_block_offset as usize;
                let end = start + (e.frame_len as usize);
                let frame = &buf[start..end];
                let block_start = block_starts[bid];
                let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                    .saturating_add(block_start)
                    .saturating_add(e.in_block_offset as u64);
                let ev = decode_stored_event_from_frame_bytes(
                    seg.shard_id as u64,
                    seg.epoch,
                    seg.segment_seq,
                    frame_off,
                    frame,
                )
                .unwrap();
                scanned.push((e.stream_hash, ev));
            }
        }

        // Compare tail/range against CPU truth for each stream.
        for s in &streams {
            let sh = *stream_hashes.get(s).unwrap();
            let mut truth: Vec<StoredEvent> = scanned
                .iter()
                .filter(|(h, _)| *h == sh)
                .map(|(_, ev)| ev.clone())
                .collect();
            truth.sort_by_key(|e| e.seq);

            let tail = storage.read_tail(tenant_id, stream_type, s, sh, 2).unwrap();
            let want_tail: Vec<StoredEvent> = truth
                .iter()
                .rev()
                .take(2)
                .cloned()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            assert_eq!(tail.len(), want_tail.len());
            for (a, b) in tail.iter().zip(want_tail.iter()) {
                assert_eq!(a.seq, b.seq);
                assert_eq!(a.event_id, b.event_id);
                assert_eq!(a.payload, b.payload);
            }

            let got = storage.read_stream(tenant_id, stream_type, s, sh, 2, 10).unwrap();
            let want_range: Vec<StoredEvent> = truth.iter().filter(|e| e.seq >= 2).take(10).cloned().collect();
            assert_eq!(got.len(), want_range.len());
            for (a, b) in got.iter().zip(want_range.iter()) {
                assert_eq!(a.seq, b.seq);
                assert_eq!(a.event_id, b.event_id);
                assert_eq!(a.payload, b.payload);
            }
        }
    }

    #[test]
    fn randomized_tail_and_range_match_cpu_reference_scan() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        #[derive(Debug)]
        struct SplitMix64 {
            state: u64,
        }

        impl SplitMix64 {
            fn new(seed: u64) -> Self {
                Self { state: seed }
            }

            fn next_u64(&mut self) -> u64 {
                let mut z = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
                self.state = z;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^ (z >> 31)
            }

            fn gen_range_u32(&mut self, upper: u32) -> u32 {
                if upper == 0 {
                    return 0;
                }
                (self.next_u64() % upper as u64) as u32
            }

            fn fill_bytes(&mut self, out: &mut [u8]) {
                for b in out {
                    *b = (self.next_u64() & 0xFF) as u8;
                }
            }
        }

        let tenant_id = "t-prop";
        let stream_type = "s-prop";
        let occurred_at = "2026-02-06T00:00:00Z";
        let ingested_at = "2026-02-06T00:00:01Z";
        let event_type = "t-prop";
        let content_type = "application/octet-stream";

        for seed in 1u64..=10u64 {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            let shard_id = 1u32;
            let epoch = 1u64;
            let paths = ShardPaths::for_root(root, shard_id);
            std::fs::create_dir_all(&paths.segments_dir).unwrap();

            let mut rng = SplitMix64::new(seed);
            let num_streams = 1 + rng.gen_range_u32(5); // 1..=5
            let num_segments = 1 + rng.gen_range_u32(4); // 1..=4

            let mut stream_ids: Vec<String> = Vec::new();
            let mut stream_hashes: Vec<u64> = Vec::new();
            for i in 0..num_streams {
                let sid = format!("s{i}");
                let h = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, &sid).unwrap();
                stream_ids.push(sid);
                stream_hashes.push(h);
            }

            // Generate per-stream monotonically increasing seq.
            let mut next_seq: Vec<u64> = vec![1u64; num_streams as usize];

            let mut manifest = OpenOptions::new()
                .create(true)
                .truncate(true)
                .read(true)
                .write(true)
                .open(&paths.manifest_path)
                .unwrap();
            let hdr = encode_manifest_header_v1(shard_id, epoch, 123).unwrap();
            manifest.write_all(&hdr).unwrap();

            let mut metas: Vec<SegmentMeta> = Vec::new();

            for seg_idx in 0..num_segments {
                let segment_seq = (seg_idx as u64) + 1;
                let segment_id = deterministic_segment_id(epoch, segment_seq);
                let created_at = 100 + segment_seq;
                let sealed_at = 200 + segment_seq;

                let codec = if (rng.next_u64() & 1) == 0 {
                    corecrux_segment::RECORD_BLOCK_CODEC_NONE_V1
                } else {
                    corecrux_segment::RECORD_BLOCK_CODEC_LZ4_V1
                };

                let frames_in_seg = 20 + rng.gen_range_u32(180); // 20..=199
                let mut events: Vec<(u64, u64, String, Vec<u8>)> = Vec::with_capacity(frames_in_seg as usize);
                for _ in 0..frames_in_seg {
                    let sidx = rng.gen_range_u32(num_streams) as usize;
                    let seq = next_seq[sidx];
                    next_seq[sidx] = seq + 1;
                    let event_id = format!("evt-{seed}-{sidx}-{seq}");
                    let payload_len = rng.gen_range_u32(256) as usize;
                    let mut payload = vec![0u8; payload_len];
                    rng.fill_bytes(&mut payload);
                    events.push((stream_hashes[sidx], seq, event_id, payload));
                }

                // Build canonical headers + frames referencing stable buffers.
                let n = events.len();
                let mut event_ids: Vec<String> = Vec::with_capacity(n);
                let mut payload_hashes: Vec<[u8; 32]> = Vec::with_capacity(n);
                let mut header_hashes: Vec<[u8; 32]> = Vec::with_capacity(n);
                let mut payload_bufs: Vec<Vec<u8>> = Vec::with_capacity(n);
                let mut header_bufs: Vec<Vec<u8>> = Vec::with_capacity(n);
                let mut stream_hashes_for_frames: Vec<u64> = Vec::with_capacity(n);
                let mut seqs: Vec<u64> = Vec::with_capacity(n);

                for (sh, seq, event_id, payload) in events {
                    stream_hashes_for_frames.push(sh);
                    seqs.push(seq);
                    event_ids.push(event_id);
                    payload_bufs.push(payload);
                    let payload_hash = compute_payload_hash(payload_bufs.last().unwrap().as_slice());

                    // stream_id is not used for hashing at this point; it is payload for header.
                    // Use a deterministic placeholder derived from stream_hash.
                    let stream_id = format!("stream-{sh:016x}");
                    let canonical = CanonicalHeaderV1 {
                        tenant_id: tenant_id.to_string(),
                        stream_id,
                        stream_type: stream_type.to_string(),
                        seq,
                        event_id: event_ids.last().unwrap().clone(),
                        occurred_at: occurred_at.to_string(),
                        ingested_at: ingested_at.to_string(),
                        event_type: event_type.to_string(),
                        content_type: content_type.to_string(),
                        payload_len: payload_bufs.last().unwrap().len() as u32,
                        payload_hash,
                    };
                    let canonical_bytes = canonical_header_bytes_v1(&canonical);
                    let header_hash = compute_header_hash(&canonical_bytes);

                    let mut hb = Vec::with_capacity(canonical_bytes.len() + 32);
                    hb.extend_from_slice(&canonical_bytes);
                    hb.extend_from_slice(&header_hash);
                    header_bufs.push(hb);

                    payload_hashes.push(payload_hash);
                    header_hashes.push(header_hash);
                }

                let mut frames: Vec<corecrux_segment::FrameInput<'_>> = Vec::with_capacity(n);
                for i in 0..n {
                    frames.push(corecrux_segment::FrameInput {
                        stream_hash: stream_hashes_for_frames[i],
                        seq: seqs[i],
                        event_id: event_ids[i].as_str(),
                        header_hash: header_hashes[i],
                        payload_hash: payload_hashes[i],
                        header_bytes: header_bufs[i].as_slice(),
                        payload_bytes: payload_bufs[i].as_slice(),
                    });
                }

                let seg = corecrux_segment::build_segment_v1_with_block_codec(
                    shard_id,
                    epoch,
                    segment_seq,
                    segment_id,
                    created_at,
                    sealed_at,
                    codec,
                    &frames,
                )
                .unwrap();

                let rel = format!("segments/seg-{segment_seq:020}-{}.ccxseg", hex16(&segment_id.0));
                let path = paths.shard_dir.join(&rel);
                std::fs::write(&path, &seg.bytes).unwrap();

                let meta = SegmentMeta {
                    level: 0,
                    shard_id,
                    epoch,
                    segment_seq,
                    segment_id,
                    relative_path: rel,
                    file_len: seg.footer.file_len,
                    created_at_unix_ns: seg.footer.created_at_unix_ns,
                    sealed_at_unix_ns: seg.footer.sealed_at_unix_ns,
                    toc_offset: seg.footer.toc_offset,
                    toc_len: seg.footer.toc_len,
                    toc_entry_count: seg.footer.toc_entry_count,
                    min_stream_hash: seg.footer.min_stream_hash,
                    min_seq: seg.footer.min_seq,
                    max_stream_hash: seg.footer.max_stream_hash,
                    max_seq: seg.footer.max_seq,
                    segment_hash: seg.footer.segment_hash,
                };
                let rec = encode_manifest_add_segment_v1(&meta).unwrap();
                let framed = frame_manifest_record(&rec);
                manifest.write_all(&framed).unwrap();
                metas.push(meta);
            }
            manifest.sync_all().unwrap();

            // Open storage (GPU-first in CUDA builds).
            let storage = ShardStorage::open(root, shard_id, epoch, ShardStorageOptions::default()).unwrap();

            // CPU truth scan.
            let mut truth_by_stream: std::collections::HashMap<u64, Vec<StoredEvent>> =
                std::collections::HashMap::new();
            for seg in &metas {
                let seg_path = paths.shard_dir.join(&seg.relative_path);
                let bytes = std::fs::read(&seg_path).unwrap();
                let (_h, toc_h, _entries, footer) = corecrux_segment::decode_segment_v1(&bytes).unwrap();
                let toc_off = footer.toc_offset as usize;
                let toc_len = footer.toc_len as usize;
                let toc_area = &bytes[toc_off..toc_off + toc_len];
                let ti = corecrux_segment::decode_trailer_index_v1(toc_area, &toc_h)
                    .unwrap()
                    .expect("trailer index");
                let block_starts = block_logical_starts(&ti.blocks).unwrap();

                let mut blocks_uncompressed: Vec<Vec<u8>> = vec![Vec::new(); ti.blocks.len()];
                for b in &ti.blocks {
                    let off = b.file_offset as usize;
                    let len = b.compressed_len as usize;
                    let end = off + len;
                    let compressed = &bytes[off..end];
                    let mut out = match b.codec {
                        corecrux_segment::RECORD_BLOCK_CODEC_NONE_V1 => compressed.to_vec(),
                        corecrux_segment::RECORD_BLOCK_CODEC_LZ4_V1 => {
                            let want = b.uncompressed_len as usize;
                            let out = lz4_flex::block::decompress(compressed, want).unwrap();
                            assert_eq!(out.len(), want);
                            out
                        }
                        other => panic!("unsupported codec {other} in prop fixture"),
                    };
                    let actual_crc = crc32c::crc32c(&out);
                    assert_eq!(actual_crc, b.crc32c);
                    blocks_uncompressed[b.block_id as usize].append(&mut out);
                }

                for e in &ti.toc_by_offset {
                    let bid = e.block_id as usize;
                    let buf = &blocks_uncompressed[bid];
                    let start = e.in_block_offset as usize;
                    let end = start + (e.frame_len as usize);
                    let frame = &buf[start..end];
                    let block_start = block_starts[bid];
                    let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                        .saturating_add(block_start)
                        .saturating_add(e.in_block_offset as u64);
                    let ev = decode_stored_event_from_frame_bytes(
                        seg.shard_id as u64,
                        seg.epoch,
                        seg.segment_seq,
                        frame_off,
                        frame,
                    )
                    .unwrap();
                    truth_by_stream.entry(e.stream_hash).or_default().push(ev);
                }
            }
            for v in truth_by_stream.values_mut() {
                v.sort_by_key(|e| e.seq);
            }

            // Random queries vs truth.
            for _ in 0..200 {
                let sidx = rng.gen_range_u32(num_streams) as usize;
                let sid = &stream_ids[sidx];
                let sh = stream_hashes[sidx];
                let truth = truth_by_stream.get(&sh).cloned().unwrap_or_default();

                // Tail.
                let tail_limit = rng.gen_range_u32(25);
                let got_tail = storage.read_tail(tenant_id, stream_type, sid, sh, tail_limit).unwrap();
                let want_tail: Vec<StoredEvent> = truth
                    .iter()
                    .rev()
                    .take(tail_limit as usize)
                    .cloned()
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                assert_eq!(got_tail.len(), want_tail.len());
                for (a, b) in got_tail.iter().zip(want_tail.iter()) {
                    assert_eq!(a.seq, b.seq);
                    assert_eq!(a.event_id, b.event_id);
                    assert_eq!(a.payload, b.payload);
                }

                // Range.
                let max_seq = truth.last().map_or(0, |e| e.seq);
                let from_seq = (rng.gen_range_u32((max_seq as u32).saturating_add(5)) as u64) + 1;
                let limit = rng.gen_range_u32(40);
                let got = storage
                    .read_stream(tenant_id, stream_type, sid, sh, from_seq, limit)
                    .unwrap();
                let take = if limit == 0 { usize::MAX } else { limit as usize };
                let want: Vec<StoredEvent> = truth.iter().filter(|e| e.seq >= from_seq).take(take).cloned().collect();
                assert_eq!(got.len(), want.len());
                for (a, b) in got.iter().zip(want.iter()) {
                    assert_eq!(a.seq, b.seq);
                    assert_eq!(a.event_id, b.event_id);
                    assert_eq!(a.payload, b.payload);
                }
            }
        }
    }

    /// Regression test: opening a second ShardStorage on the same shard while the
    /// first is held must fail with EAGAIN / WouldBlock, NOT silently succeed.
    /// This validates that the flock-based exclusive lock prevents self-lock reentry,
    /// which was the root cause of the decision-plane 500 bug (2026-03-24).
    #[test]
    fn second_open_on_locked_shard_returns_would_block() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (dir, _storage) = open_test_storage(ShardStorageOptions::default());

        // Attempt to open the same shard while the first handle is live.

        let result = ShardStorage::open(dir.path(), 1, 1, ShardStorageOptions::default());

        let err = match result {
            Ok(_) => panic!("second open should fail while first holds flock"),
            Err(e) => e,
        };
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("temporarily unavailable")
                || err_msg.contains("Would block")
                || err_msg.contains("os error 11")
                || err_msg.contains("WouldBlock"),
            "error should indicate lock contention, got: {err_msg}"
        );
    }

    // ── Pure function coverage: encode/decode helpers ──────────────────

    #[test]
    fn dir_extent_encode_decode_roundtrip() {
        let e = DirExtentV1 {
            stream_hash: 0xDEAD_BEEF_CAFE_BABE,
            min_seq: 42,
            max_seq: 99,
            segment_seq: 7,
        };
        let bytes = encode_dir_extent_v1(e);
        let decoded = decode_dir_extent_v1(&bytes).unwrap();
        assert_eq!(decoded.stream_hash, e.stream_hash);
        assert_eq!(decoded.min_seq, e.min_seq);
        assert_eq!(decoded.max_seq, e.max_seq);
        assert_eq!(decoded.segment_seq, e.segment_seq);
    }

    #[test]
    fn decode_dir_extent_v1_too_small() {
        let err = decode_dir_extent_v1(&[0u8; 16]).unwrap_err();
        assert!(err.to_string().contains("dir extent too small"));
    }

    #[test]
    fn dirrun_partition_v1_stable() {
        assert_eq!(dirrun_partition_v1(0x00), 0);
        assert_eq!(dirrun_partition_v1(0xFF), 255);
        assert_eq!(dirrun_partition_v1(0x1234_5678_9ABC_DEF0), 0xF0);
    }

    #[test]
    fn dir_extent_key_cmp_orders_by_stream_hash_then_segment_seq() {
        let a = DirExtentV1 {
            stream_hash: 1,
            min_seq: 0,
            max_seq: 0,
            segment_seq: 10,
        };
        let b = DirExtentV1 {
            stream_hash: 2,
            min_seq: 0,
            max_seq: 0,
            segment_seq: 5,
        };
        assert!(dir_extent_key_cmp(&a, &b).is_lt());

        let c = DirExtentV1 {
            stream_hash: 1,
            min_seq: 0,
            max_seq: 0,
            segment_seq: 20,
        };
        assert!(dir_extent_key_cmp(&a, &c).is_lt());

        assert!(dir_extent_key_cmp(&a, &a).is_eq());
    }

    #[test]
    fn dir_run_relative_path_v1_format() {
        assert_eq!(
            dir_run_relative_path_v1(0, 42),
            "directory/dirrun-l0-r00000000000000000042.ccxdir"
        );
        assert_eq!(
            dir_run_relative_path_v1(3, 0),
            "directory/dirrun-l3-r00000000000000000000.ccxdir"
        );
    }

    #[test]
    fn merge_dir_extents_empty_inputs() {
        let result = merge_dir_extents_partition_sorted_unique_cpu(&[], &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn merge_dir_extents_one_empty() {
        let a = vec![DirExtentV1 {
            stream_hash: 1,
            min_seq: 5,
            max_seq: 10,
            segment_seq: 1,
        }];
        let result = merge_dir_extents_partition_sorted_unique_cpu(&a, &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].stream_hash, 1);

        let result2 = merge_dir_extents_partition_sorted_unique_cpu(&[], &a);
        assert_eq!(result2.len(), 1);
        assert_eq!(result2[0].stream_hash, 1);
    }

    #[test]
    fn merge_dir_extents_deduplicates_same_key() {
        let a = vec![DirExtentV1 {
            stream_hash: 1,
            min_seq: 5,
            max_seq: 10,
            segment_seq: 1,
        }];
        let b = vec![DirExtentV1 {
            stream_hash: 1,
            min_seq: 3,
            max_seq: 12,
            segment_seq: 1,
        }];
        let result = merge_dir_extents_partition_sorted_unique_cpu(&a, &b);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].min_seq, 3);
        assert_eq!(result[0].max_seq, 12);
    }

    #[test]
    fn merge_dir_extents_interleaved() {
        let a = vec![
            DirExtentV1 {
                stream_hash: 1,
                min_seq: 1,
                max_seq: 5,
                segment_seq: 1,
            },
            DirExtentV1 {
                stream_hash: 3,
                min_seq: 1,
                max_seq: 3,
                segment_seq: 1,
            },
        ];
        let b = vec![
            DirExtentV1 {
                stream_hash: 2,
                min_seq: 1,
                max_seq: 2,
                segment_seq: 1,
            },
            DirExtentV1 {
                stream_hash: 4,
                min_seq: 1,
                max_seq: 4,
                segment_seq: 1,
            },
        ];
        let result = merge_dir_extents_partition_sorted_unique_cpu(&a, &b);
        assert_eq!(result.len(), 4);
        assert_eq!(result[0].stream_hash, 1);
        assert_eq!(result[1].stream_hash, 2);
        assert_eq!(result[2].stream_hash, 3);
        assert_eq!(result[3].stream_hash, 4);
    }

    // ── Commit frame edge cases ────────────────────────────────────────

    #[test]
    fn decode_commit_frame_v1_too_small() {
        let err = decode_commit_frame_v1(&[0u8; 10]).unwrap_err();
        assert!(err.to_string().contains("commit frame too small"));
    }

    #[test]
    fn decode_commit_frame_v1_bad_magic() {
        let mut frame = encode_commit_frame_v1(1, 2, 3, 4);
        frame[0] = 0xFF; // corrupt magic
        let err = decode_commit_frame_v1(&frame).unwrap_err();
        assert!(err.to_string().contains("invalid commit frame magic"));
    }

    #[test]
    fn decode_commit_frame_v1_bad_version() {
        let mut frame = encode_commit_frame_v1(1, 2, 3, 4);
        frame[4] = 99; // corrupt version
                       // Recalculate CRC so it passes the CRC check
        let crc = crc32c::crc32c(&frame[..COMMIT_FRAME_LEN_V1 - 4]);
        frame[COMMIT_FRAME_LEN_V1 - 4..].copy_from_slice(&crc.to_le_bytes());
        let err = decode_commit_frame_v1(&frame).unwrap_err();
        assert!(err.to_string().contains("unsupported commit frame version"));
    }

    #[test]
    fn decode_commit_frame_v1_bad_header_len() {
        let mut frame = encode_commit_frame_v1(1, 2, 3, 4);
        frame[6] = 128; // corrupt header_len
        let crc = crc32c::crc32c(&frame[..COMMIT_FRAME_LEN_V1 - 4]);
        frame[COMMIT_FRAME_LEN_V1 - 4..].copy_from_slice(&crc.to_le_bytes());
        let err = decode_commit_frame_v1(&frame).unwrap_err();
        assert!(err.to_string().contains("invalid commit frame header_len"));
    }

    // ── Manifest header validation ─────────────────────────────────────

    #[test]
    fn validate_manifest_header_too_small() {
        let err = validate_manifest_header(&[0u8; 10]).unwrap_err();
        assert!(err.to_string().contains("too small"));
    }

    #[test]
    fn validate_manifest_header_bad_magic() {
        let mut hdr = encode_manifest_header_v1(0, 1, 100).unwrap();
        hdr[0] = 0xFF;
        let err = validate_manifest_header(&hdr).unwrap_err();
        assert!(err.to_string().contains("bad magic"));
    }

    #[test]
    fn validate_manifest_header_bad_version() {
        let mut hdr = encode_manifest_header_v1(0, 1, 100).unwrap();
        hdr[4] = 99;
        let crc = crc32c::crc32c(&hdr[..MANIFEST_HEADER_LEN - 4]);
        hdr[MANIFEST_HEADER_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
        let err = validate_manifest_header(&hdr).unwrap_err();
        assert!(err.to_string().contains("bad version"));
    }

    #[test]
    fn validate_manifest_header_bad_header_len() {
        let mut hdr = encode_manifest_header_v1(0, 1, 100).unwrap();
        hdr[8..12].copy_from_slice(&999u32.to_le_bytes());
        let crc = crc32c::crc32c(&hdr[..MANIFEST_HEADER_LEN - 4]);
        hdr[MANIFEST_HEADER_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
        let err = validate_manifest_header(&hdr).unwrap_err();
        assert!(err.to_string().contains("bad header_len"));
    }

    #[test]
    fn validate_manifest_header_crc_mismatch() {
        let mut hdr = encode_manifest_header_v1(0, 1, 100).unwrap();
        hdr[MANIFEST_HEADER_LEN - 4..].copy_from_slice(&0xDEADu32.to_le_bytes());
        let err = validate_manifest_header(&hdr).unwrap_err();
        match err {
            StorageError::ManifestCrcMismatch { .. } => {}
            other => panic!("expected ManifestCrcMismatch, got {other:?}"),
        }
    }

    #[test]
    fn validate_manifest_header_valid_roundtrip() {
        let hdr = encode_manifest_header_v1(42, 7, 12345).unwrap();
        validate_manifest_header(&hdr).expect("valid manifest header");
    }

    // ── Pure helpers ───────────────────────────────────────────────────

    #[test]
    fn blake3_hash16_produces_16_byte_prefix() {
        let h = blake3_hash16(b"hello");
        assert_eq!(h.len(), 16);
        let full = blake3::hash(b"hello");
        assert_eq!(&h[..], &full.as_bytes()[..16]);
    }

    #[test]
    fn normalize_hash16_prefix_zeroes_beyond_keep() {
        let h = [0xFFu8; 16];
        let result = normalize_hash16_prefix(h, 4);
        assert_eq!(&result[..4], &[0xFF; 4]);
        assert_eq!(&result[4..], &[0u8; 12]);
    }

    #[test]
    fn normalize_hash16_prefix_zero_zeroes_all() {
        let h = [0xAB; 16];
        let result = normalize_hash16_prefix(h, 0);
        assert_eq!(result, [0u8; 16]);
    }

    #[test]
    fn normalize_hash16_prefix_16_keeps_all() {
        let h = [0xAB; 16];
        let result = normalize_hash16_prefix(h, 16);
        assert_eq!(result, h);
    }

    #[test]
    fn normalize_hash16_prefix_beyond_16_keeps_all() {
        let h = [0xAB; 16];
        let result = normalize_hash16_prefix(h, 32);
        assert_eq!(result, h);
    }

    #[test]
    fn parse_segment_seq_from_filename_valid() {
        assert_eq!(
            parse_segment_seq_from_filename("seg-00000000000000000042-abc.ccxseg"),
            Some(42)
        );
        assert_eq!(
            parse_segment_seq_from_filename("seg-00000000000000000001-deadbeef.ccxseg"),
            Some(1)
        );
    }

    #[test]
    fn parse_segment_seq_from_filename_invalid() {
        assert_eq!(parse_segment_seq_from_filename("not-a-segment"), None);
        assert_eq!(parse_segment_seq_from_filename("seg-short-x"), None);
        assert_eq!(parse_segment_seq_from_filename(""), None);
    }

    #[test]
    fn deterministic_segment_id_encodes_epoch_and_seq() {
        let id = deterministic_segment_id(7, 42);
        assert_eq!(&id.0[0..8], &7u64.to_le_bytes());
        assert_eq!(&id.0[8..16], &42u64.to_le_bytes());
    }

    #[test]
    fn rejected_outcome_sets_fields() {
        let o = rejected_outcome("MY_CODE", "my message".to_string());
        assert_eq!(o.status, AppendStatus::Rejected);
        assert_eq!(o.seq, 0);
        assert!(o.location.is_none());
        assert_eq!(o.error_code.as_deref(), Some("MY_CODE"));
        assert_eq!(o.error_message.as_deref(), Some("my message"));
    }

    #[test]
    fn compute_write_confirmation_receipt_hash_deterministic() {
        let frames = vec![b"frame1".to_vec(), b"frame2".to_vec()];
        let h1 = compute_write_confirmation_receipt_hash(&frames);
        let h2 = compute_write_confirmation_receipt_hash(&frames);
        assert_eq!(h1, h2);

        let frames2 = vec![b"frame2".to_vec(), b"frame1".to_vec()];
        let h3 = compute_write_confirmation_receipt_hash(&frames2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn compute_write_confirmation_receipt_hash_empty() {
        let h = compute_write_confirmation_receipt_hash(&[]);
        // Empty hasher produces the BLAKE3 empty-input hash
        assert_eq!(h, *blake3::Hasher::new().finalize().as_bytes());
    }

    #[test]
    fn failpoint_active_returns_false_by_default() {
        clear_test_failpoint();
        assert!(!failpoint_active("whatever"));
    }

    // ── Dirrun decode error paths ─────────────────────────────────────

    #[test]
    fn decode_dir_run_v1_too_small() {
        let err = decode_dir_run_v1(&[0u8; 100]).unwrap_err();
        assert!(err.to_string().contains("dirrun file too small"));
    }

    #[test]
    fn decode_dir_run_v1_bad_magic() {
        let bytes = encode_dir_run_v1(0, &[]).unwrap();
        let mut bad = bytes.clone();
        bad[0] = 0xFF;
        let err = decode_dir_run_v1(&bad).unwrap_err();
        assert!(err.to_string().contains("dirrun bad magic"));
    }

    #[test]
    fn dirrun_empty_extents_roundtrip() {
        let bytes = encode_dir_run_v1(42, &[]).unwrap();
        let decoded = decode_dir_run_v1(&bytes).unwrap();
        assert_eq!(decoded.created_at_unix_ns, 42);
        assert_eq!(decoded.record_count, 0);
        for p in &decoded.partitions {
            assert!(p.is_empty());
        }
    }

    // ── IdemHotCache edge cases ───────────────────────────────────────

    #[test]
    fn idem_hot_cache_zero_capacity() {
        let mut cache = IdemHotCache::new(0);
        let key = IdemKey {
            stream_hash: 1,
            event_id_hash16: [0u8; 16],
        };
        let entry = IdemEntry {
            seq: 1,
            loc: FrameLocation {
                shard_id: 0,
                epoch: 0,
                segment_seq: 0,
                offset: 0,
            },
        };
        cache.insert(key, entry);
        assert!(cache.is_incomplete());
        assert!(cache.candidates(&key).is_none());
    }

    #[test]
    fn idem_hot_cache_eviction() {
        let mut cache = IdemHotCache::new(2);
        let key1 = IdemKey {
            stream_hash: 1,
            event_id_hash16: [1u8; 16],
        };
        let key2 = IdemKey {
            stream_hash: 2,
            event_id_hash16: [2u8; 16],
        };
        let key3 = IdemKey {
            stream_hash: 3,
            event_id_hash16: [3u8; 16],
        };
        let loc = FrameLocation {
            shard_id: 0,
            epoch: 0,
            segment_seq: 0,
            offset: 0,
        };

        cache.insert(key1, IdemEntry { seq: 1, loc });
        cache.insert(key2, IdemEntry { seq: 2, loc });
        assert!(!cache.is_incomplete());

        cache.insert(key3, IdemEntry { seq: 3, loc });
        assert!(cache.is_incomplete());
        // key1 should have been evicted
        assert!(cache.candidates(&key1).is_none());
        assert!(cache.candidates(&key3).is_some());
    }

    // ── ColdBatchLookup ───────────────────────────────────────────────

    #[test]
    fn cold_batch_lookup_find_works() {
        let mut lookup = ColdBatchLookup::default();
        let prefix = [0xAAu8; 16];
        let outcome = AppendOutcome {
            status: AppendStatus::DuplicateCommitted,
            seq: 42,
            location: None,
            payload_hash: [0u8; 32],
            header_hash: [0u8; 32],
            error_code: None,
            error_message: None,
        };
        lookup.by_prefix.entry(prefix).or_default().push(ColdBatchMatch {
            event_id: "evt-1".to_string(),
            outcome: outcome.clone(),
        });
        let found = lookup.find(prefix, "evt-1").unwrap();
        assert_eq!(found.seq, 42);
        assert!(lookup.find(prefix, "evt-2").is_none());
        assert!(lookup.find([0xBBu8; 16], "evt-1").is_none());
    }

    // ── frame_manifest_record ─────────────────────────────────────────

    #[test]
    fn frame_manifest_record_structure() {
        let data = b"test record";
        let framed = frame_manifest_record(data);
        assert_eq!(framed.len(), 8 + data.len());
        let len = u32::from_le_bytes(framed[0..4].try_into().unwrap());
        assert_eq!(len, data.len() as u32);
        let crc = u32::from_le_bytes(framed[4..8].try_into().unwrap());
        assert_eq!(crc, crc32c::crc32c(data));
        assert_eq!(&framed[8..], data);
    }

    // ── encode_manifest_header_v1 deterministic ───────────────────────

    #[test]
    fn encode_manifest_header_v1_fields() {
        let hdr = encode_manifest_header_v1(42, 7, 999).unwrap();
        let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        assert_eq!(magic, MANIFEST_MAGIC_CCMF);
        let ver = u16::from_le_bytes(hdr[4..6].try_into().unwrap());
        assert_eq!(ver, MANIFEST_VERSION_V1);
        let shard_id = u32::from_le_bytes(hdr[12..16].try_into().unwrap());
        assert_eq!(shard_id, 42);
        let epoch = u64::from_le_bytes(hdr[16..24].try_into().unwrap());
        assert_eq!(epoch, 7);
        let created = u64::from_le_bytes(hdr[24..32].try_into().unwrap());
        assert_eq!(created, 999);
    }

    // ── ShardStorageOptions invalid hash prefix ───────────────────────

    #[test]
    fn open_rejects_invalid_hash_prefix_len() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        let opts = ShardStorageOptions {
            event_id_hash_prefix_len: 0,
            ..Default::default()
        };
        match ShardStorage::open(dir.path(), 1, 1, opts) {
            Err(StorageError::InvalidArgument { code, .. }) => {
                assert_eq!(code, "CONFIG_INVALID");
            }
            Err(other) => panic!("expected InvalidArgument, got: {other}"),
            Ok(_) => panic!("expected error, got Ok"),
        }

        let opts17 = ShardStorageOptions {
            event_id_hash_prefix_len: 17,
            ..Default::default()
        };
        match ShardStorage::open(dir.path(), 1, 1, opts17) {
            Err(StorageError::InvalidArgument { code, .. }) => {
                assert_eq!(code, "CONFIG_INVALID");
            }
            Err(other) => panic!("expected InvalidArgument, got: {other}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    // ── ReadStatsV1 / AppendStatsV1 accumulator methods ───────────────

    #[test]
    fn read_stats_accumulates_durations() {
        let mut stats = ReadStatsV1::default();
        stats.add_index_elapsed(std::time::Duration::from_nanos(100));
        stats.add_io_elapsed(std::time::Duration::from_nanos(200));
        stats.add_decode_elapsed(std::time::Duration::from_nanos(300));
        assert_eq!(stats.index_lookup_nanos, 100);
        assert_eq!(stats.io_nanos, 200);
        assert_eq!(stats.decode_nanos, 300);

        // Accumulates, doesn't replace
        stats.add_index_elapsed(std::time::Duration::from_nanos(50));
        assert_eq!(stats.index_lookup_nanos, 150);
    }

    #[test]
    fn append_stats_accumulates_durations() {
        let mut stats = AppendStatsV1::default();
        stats.add_idempotency_elapsed(std::time::Duration::from_nanos(10));
        stats.add_index_elapsed(std::time::Duration::from_nanos(20));
        stats.add_io_write_elapsed(std::time::Duration::from_nanos(30));
        stats.add_fence_fsync_elapsed(std::time::Duration::from_nanos(40));
        assert_eq!(stats.idempotency_check_nanos, 10);
        assert_eq!(stats.index_update_nanos, 20);
        assert_eq!(stats.io_write_nanos, 30);
        assert_eq!(stats.fence_fsync_nanos, 40);
        assert_eq!(stats.fence_nanos, 40); // fence_fsync adds to fence_nanos too
    }

    // ── ShardPaths ────────────────────────────────────────────────────

    #[test]
    fn shard_paths_for_root_format() {
        let paths = ShardPaths::for_root(std::path::Path::new("/data"), 42);
        assert!(paths.shard_dir.to_str().unwrap().contains("shard-0042"));
        assert!(paths.lock_path.to_str().unwrap().ends_with("LOCK"));
        assert!(paths.manifest_path.to_str().unwrap().ends_with("MANIFEST"));
        assert!(paths.segments_dir.to_str().unwrap().ends_with("segments"));
        assert!(paths.directory_dir.to_str().unwrap().ends_with("directory"));
        assert!(paths.projections_dir.to_str().unwrap().ends_with("projections"));
        assert!(paths.tmp_dir.to_str().unwrap().ends_with("tmp"));
        assert!(paths.quarantine_dir.to_str().unwrap().ends_with("quarantine"));
    }

    // ── StorageError Display ──────────────────────────────────────────

    #[test]
    fn storage_error_display_includes_codes() {
        let e = StorageError::InvalidArgument {
            code: "X".into(),
            msg: "Y".into(),
        };
        assert!(e.to_string().contains('X'));
        assert!(e.to_string().contains('Y'));

        let e2 = StorageError::ResourceExhausted {
            code: "BP".into(),
            msg: "full".into(),
            retry_after_ms: Some(500),
        };
        assert!(e2.to_string().contains("BP"));

        let e3 = StorageError::ManifestCrcMismatch {
            expected: 0xAA,
            actual: 0xBB,
        };
        assert!(e3.to_string().contains("0xaa"));
        assert!(e3.to_string().contains("0xbb"));
    }

    // ── head_stream_tail_index ────────────────────────────────────────

    #[test]
    fn build_head_stream_tail_index_groups_by_stream() {
        let frames = vec![
            HeadFrameMeta {
                stream_hash: 1,
                seq: 1,
                record_off: 0,
                frame_len: 10,
                payload_len: 5,
                event_id_hash16: [0u8; 16],
                header_digest8: [0u8; 8],
                payload_digest8: [0u8; 8],
                block_id: 0,
                in_block_offset: 0,
            },
            HeadFrameMeta {
                stream_hash: 2,
                seq: 1,
                record_off: 10,
                frame_len: 10,
                payload_len: 5,
                event_id_hash16: [0u8; 16],
                header_digest8: [0u8; 8],
                payload_digest8: [0u8; 8],
                block_id: 0,
                in_block_offset: 10,
            },
            HeadFrameMeta {
                stream_hash: 1,
                seq: 2,
                record_off: 20,
                frame_len: 10,
                payload_len: 5,
                event_id_hash16: [0u8; 16],
                header_digest8: [0u8; 8],
                payload_digest8: [0u8; 8],
                block_id: 0,
                in_block_offset: 20,
            },
        ];
        let idx = build_head_stream_tail_index(&frames);
        assert_eq!(idx.len(), 2);
        assert_eq!(idx[&1].len(), 2);
        assert_eq!(idx[&2].len(), 1);
    }

    #[test]
    fn push_head_stream_tail_index_caps_at_max() {
        let mut idx: HashMap<u64, Vec<HeadTailFrameRef>> = HashMap::new();
        for i in 0..HEAD_STREAM_TAIL_INDEX_MAX_EVENTS + 10 {
            push_head_stream_tail_index(&mut idx, 1, i, i as u64);
        }
        assert_eq!(idx[&1].len(), HEAD_STREAM_TAIL_INDEX_MAX_EVENTS);
    }

    // ── should_skip_startup_dirrun_bootstrap boundary ─────────────────

    #[test]
    fn should_skip_dirrun_bootstrap_boundaries() {
        // dir_runs_empty=false always returns false
        assert!(!should_skip_startup_dirrun_bootstrap(false, 0));
        assert!(!should_skip_startup_dirrun_bootstrap(false, usize::MAX));

        // At the limit: not skipped
        assert!(!should_skip_startup_dirrun_bootstrap(
            true,
            STARTUP_DIRRUN_BOOTSTRAP_SEGMENT_LIMIT_V1
        ));
        // One over: skipped
        assert!(should_skip_startup_dirrun_bootstrap(
            true,
            STARTUP_DIRRUN_BOOTSTRAP_SEGMENT_LIMIT_V1 + 1
        ));
    }

    // ── Manifest with CRC mismatch ───────────────────────────────────

    #[test]
    fn manifest_record_crc_mismatch_truncates_gracefully() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("MANIFEST");

        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();

        let hdr = encode_manifest_header_v1(0, 1, 100).unwrap();
        f.write_all(&hdr).unwrap();

        // Write a record with wrong CRC
        let data = b"fake record";
        let len = data.len() as u32;
        f.write_all(&len.to_le_bytes()).unwrap();
        f.write_all(&0xDEADu32.to_le_bytes()).unwrap(); // wrong CRC
        f.write_all(data).unwrap();
        f.sync_all().unwrap();

        let (state, end) = load_manifest_records(&mut f).unwrap();
        // Should have truncated to just the header
        assert_eq!(end, MANIFEST_HEADER_LEN as u64);
        assert!(state.segments_by_seq.is_empty());
    }

    // ── Backpressure max batch bytes ─────────────────────────────────

    #[test]
    fn backpressure_max_batch_bytes_rejects() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let opts = ShardStorageOptions {
            max_batch_bytes: 1, // extremely small
            ..Default::default()
        };
        let (_dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        let events = [AppendEventInput {
            event_id: "e1",
            occurred_at: "2026-02-06T00:00:00Z",
            event_type: "t",
            content_type: "application/octet-stream",
            payload_bytes: b"hello world",
        }];

        let err = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &events,
            )
            .unwrap_err();
        match err {
            StorageError::ResourceExhausted { code, .. } => {
                assert_eq!(code, "BACKPRESSURE_MAX_BATCH_BYTES");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    // ── Replay from sealed ──────────────────────────────────────────

    #[test]
    fn replay_from_sealed_empty_store() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, storage) = open_test_storage(ShardStorageOptions::default());
        let (frames, cursor) = storage.replay_from_sealed(None, 100).unwrap();
        assert!(frames.is_empty());
        assert!(cursor.is_none());
    }

    // ── Force seal with no head ──────────────────────────────────────

    #[test]
    fn force_seal_head_with_no_head() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());
        let result = storage.force_seal_head().unwrap();
        assert!(!result.sealed);
        assert!(result.segment_seq.is_none());
        assert!(result.frame_count.is_none());
    }

    // ── DirectoryLsmStats ─────────────────────────────────────────────

    #[test]
    fn directory_lsm_stats_empty() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, storage) = open_test_storage(ShardStorageOptions::default());
        let stats = storage.directory_lsm_stats_v1();
        assert!(stats.levels.is_empty());
    }

    #[test]
    fn build_ccxi_companion_writes_index_and_uses_stream_hash_fallback_for_bad_headers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let shard_dir = dir.path();
        std::fs::create_dir_all(shard_dir.join("tmp")).expect("tmp dir");
        std::fs::create_dir_all(shard_dir.join("segments")).expect("segments dir");

        let (frame_a, mut meta_a, _) =
            build_ccxi_test_frame("tenant-a", "artifact", "stream-a", 1, "evt-a", br"alpha alpha beta", 0);

        let fallback_stream_hash = 0xABCD_EF01_2345_6789;
        let (frame_b, mut meta_b) =
            build_ccxi_raw_frame(b"not-a-canonical-header", b"gamma", fallback_stream_hash, 2, 0);

        meta_b.record_off = frame_a.len() as u32;
        let mut record_area = frame_a;
        record_area.extend_from_slice(&frame_b);
        meta_a.record_off = 0;

        let segment_id = SegmentId([0x11; 16]);
        build_ccxi_companion(shard_dir, 7, 3, 42, &segment_id, &record_area, &[meta_a, meta_b])
            .expect("build companion");

        let final_path = shard_dir.join(format!("segments/seg-{:020}-{}.ccxi", 42, hex16(&segment_id.0)));
        let ccxi = std::fs::read(&final_path).expect("read ccxi");
        let reader = corecrux_index::CcxiReader::from_bytes(&ccxi).expect("parse ccxi");

        assert_eq!(reader.header.shard_id, 7);
        assert_eq!(reader.header.segment_seq, 42);
        assert_eq!(reader.header.epoch, 3);
        assert_eq!(reader.header.total_frames, 2);
        assert_eq!(reader.docs.len(), 2);

        let tenant_hash = xxhash_rust::xxh64::xxh64(b"tenant-a", 0);
        assert_eq!(reader.docs[0].tenant_hash_full, tenant_hash);
        assert_eq!(reader.docs[1].tenant_hash_full, fallback_stream_hash);

        let alpha_hash = corecrux_index::tokenize("alpha").first().expect("alpha token").hash;
        let alpha_entry = reader.find_token(alpha_hash).expect("alpha postings");
        let (alpha_docs, alpha_tfs) = reader.decode_postings(alpha_entry);
        assert_eq!(alpha_docs, vec![0]);
        assert_eq!(alpha_tfs, vec![2]);

        let gamma_hash = corecrux_index::tokenize("gamma").first().expect("gamma token").hash;
        let gamma_entry = reader.find_token(gamma_hash).expect("gamma postings");
        let (gamma_docs, gamma_tfs) = reader.decode_postings(gamma_entry);
        assert_eq!(gamma_docs, vec![1]);
        assert_eq!(gamma_tfs, vec![1]);
    }

    #[test]
    fn build_ccxi_companion_skips_malformed_and_non_indexable_frames_without_writing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let shard_dir = dir.path();
        std::fs::create_dir_all(shard_dir.join("tmp")).expect("tmp dir");
        std::fs::create_dir_all(shard_dir.join("segments")).expect("segments dir");

        let short_frame = b"tiny".to_vec();
        let truncated_frame = {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&corecrux_segment::FRAME_MAGIC_CRX1.to_le_bytes());
            bytes.extend_from_slice(&corecrux_segment::FRAME_VERSION_V1.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&32u32.to_le_bytes());
            bytes
        };
        let (empty_frame, _) = build_ccxi_raw_frame(b"bad-header", b"", 1, 1, 0);
        let (binary_frame, _) = build_ccxi_raw_frame(b"bad-header", &[0xff, 0xfe, 0xfd], 2, 2, 0);

        let mut record_area = Vec::new();
        let short_off = record_area.len() as u32;
        record_area.extend_from_slice(&short_frame);
        let truncated_off = record_area.len() as u32;
        record_area.extend_from_slice(&truncated_frame);
        let empty_off = record_area.len() as u32;
        record_area.extend_from_slice(&empty_frame);
        let binary_off = record_area.len() as u32;
        record_area.extend_from_slice(&binary_frame);

        let metas = vec![
            FrameMetaV1 {
                stream_hash: 1,
                seq: 1,
                record_off: short_off,
                frame_len: short_frame.len() as u32,
                payload_len: 0,
                event_id_hash16: [0; 16],
                header_digest8: [0; 8],
                payload_digest8: [0; 8],
            },
            FrameMetaV1 {
                stream_hash: 2,
                seq: 2,
                record_off: truncated_off,
                frame_len: truncated_frame.len() as u32,
                payload_len: 32,
                event_id_hash16: [0; 16],
                header_digest8: [0; 8],
                payload_digest8: [0; 8],
            },
            FrameMetaV1 {
                stream_hash: 3,
                seq: 3,
                record_off: empty_off,
                frame_len: empty_frame.len() as u32,
                payload_len: 0,
                event_id_hash16: [0; 16],
                header_digest8: [0; 8],
                payload_digest8: [0; 8],
            },
            FrameMetaV1 {
                stream_hash: 4,
                seq: 4,
                record_off: binary_off,
                frame_len: binary_frame.len() as u32,
                payload_len: 3,
                event_id_hash16: [0; 16],
                header_digest8: [0; 8],
                payload_digest8: [0; 8],
            },
            FrameMetaV1 {
                stream_hash: 5,
                seq: 5,
                record_off: record_area.len() as u32 + 10,
                frame_len: 16,
                payload_len: 0,
                event_id_hash16: [0; 16],
                header_digest8: [0; 8],
                payload_digest8: [0; 8],
            },
        ];

        let segment_id = SegmentId([0x22; 16]);
        build_ccxi_companion(shard_dir, 9, 4, 77, &segment_id, &record_area, &metas).expect("skip malformed frames");

        let final_path = shard_dir.join(format!("segments/seg-{:020}-{}.ccxi", 77, hex16(&segment_id.0)));
        assert!(
            !final_path.exists(),
            "non-indexable frames should not produce a ccxi file"
        );
    }

    // ── append error paths + end-to-end read/replay (coverage batch) ─────

    fn ev<'a>(event_id: &'a str, payload: &'a [u8]) -> AppendEventInput<'a> {
        AppendEventInput {
            event_id,
            occurred_at: "2026-06-17T00:00:00Z",
            event_type: "evt.created",
            content_type: "application/json",
            payload_bytes: payload,
        }
    }

    fn append_n(storage: &mut ShardStorage, stream_hash: u64, tenant: &str, st: &str, sid: &str, n: u64) {
        for i in 1..=n {
            let id = format!("e{i}");
            let payload = format!("payload-{i}");
            let out = storage
                .append_batch(
                    stream_hash,
                    0,
                    tenant,
                    st,
                    sid,
                    "2026-06-17T00:00:01Z",
                    &[ev(&id, payload.as_bytes())],
                )
                .expect("append ok");
            assert_eq!(out[0].status, AppendStatus::Appended);
            assert_eq!(out[0].seq, i);
        }
    }

    #[test]
    fn append_rejects_batch_exceeding_max_events() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut opts = ShardStorageOptions::default();
        opts.max_events_per_batch = 1;
        let (_dir, mut storage) = open_test_storage(opts);
        let sh = corecrux_frame::stream_hash_xxhash64("t", "a", "s").unwrap();
        let err = storage
            .append_batch(
                sh,
                0,
                "t",
                "a",
                "s",
                "2026-06-17T00:00:01Z",
                &[ev("e1", b"x"), ev("e2", b"y")],
            )
            .expect_err("too many events");
        match err {
            StorageError::ResourceExhausted { code, .. } => assert_eq!(code, "BACKPRESSURE_MAX_EVENTS"),
            other => panic!("unexpected: {other}"),
        }
    }

    #[test]
    fn append_rejects_oversized_batch_bytes() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut opts = ShardStorageOptions::default();
        opts.max_batch_bytes = 8;
        let (_dir, mut storage) = open_test_storage(opts);
        let sh = corecrux_frame::stream_hash_xxhash64("t", "a", "s").unwrap();
        let err = storage
            .append_batch(
                sh,
                0,
                "t",
                "a",
                "s",
                "2026-06-17T00:00:01Z",
                &[ev("e1", b"a-large-payload")],
            )
            .expect_err("oversized batch");
        match err {
            StorageError::ResourceExhausted { code, .. } => assert_eq!(code, "BACKPRESSURE_MAX_BATCH_BYTES"),
            other => panic!("unexpected: {other}"),
        }
    }

    #[test]
    fn append_rejects_sequence_mismatch() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());
        let sh = corecrux_frame::stream_hash_xxhash64("t", "a", "s").unwrap();
        let err = storage
            .append_batch(sh, 99, "t", "a", "s", "2026-06-17T00:00:01Z", &[ev("e1", b"x")])
            .expect_err("seq mismatch");
        assert!(matches!(err, StorageError::ManifestRecordInvalid { .. }));
    }

    #[test]
    fn append_per_event_rejections_empty_and_oversized_id() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut opts = ShardStorageOptions::default();
        opts.max_event_id_bytes = 4;
        let (_dir, mut storage) = open_test_storage(opts);
        let sh = corecrux_frame::stream_hash_xxhash64("t", "a", "s").unwrap();
        let out = storage
            .append_batch(
                sh,
                0,
                "t",
                "a",
                "s",
                "2026-06-17T00:00:01Z",
                &[ev("", b"x"), ev("toolongid", b"y"), ev("ok", b"z")],
            )
            .expect("batch returns per-event outcomes");
        assert_eq!(out[0].status, AppendStatus::Rejected, "empty id rejected");
        assert_eq!(out[1].status, AppendStatus::Rejected, "oversized id rejected");
        assert_eq!(out[2].status, AppendStatus::Appended, "valid id appended");
    }

    #[test]
    fn append_idempotent_duplicate_across_batches() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());
        let sh = corecrux_frame::stream_hash_xxhash64("t", "a", "s").unwrap();
        let first = storage
            .append_batch(sh, 0, "t", "a", "s", "2026-06-17T00:00:01Z", &[ev("dup", b"v1")])
            .unwrap();
        assert_eq!(first[0].status, AppendStatus::Appended);
        let again = storage
            .append_batch(sh, 0, "t", "a", "s", "2026-06-17T00:00:02Z", &[ev("dup", b"v1")])
            .unwrap();
        assert_eq!(again[0].status, AppendStatus::DuplicateCommitted);
        assert_eq!(again[0].seq, first[0].seq, "duplicate keeps original seq");
    }

    #[test]
    fn append_dedupes_within_single_batch() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());
        let sh = corecrux_frame::stream_hash_xxhash64("t", "a", "s").unwrap();
        let out = storage
            .append_batch(
                sh,
                0,
                "t",
                "a",
                "s",
                "2026-06-17T00:00:01Z",
                &[ev("d", b"x"), ev("d", b"x")],
            )
            .unwrap();
        assert_eq!(out[0].status, AppendStatus::Appended);
        assert_eq!(out[1].status, AppendStatus::DuplicateInBatch);
    }

    #[test]
    fn read_stream_ranges_and_tail() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());
        let sh = corecrux_frame::stream_hash_xxhash64("t", "a", "s").unwrap();
        append_n(&mut storage, sh, "t", "a", "s", 5);

        // from seq 3, max 2 → seq 3,4.
        let mid = storage.read_stream("t", "a", "s", sh, 3, 2).unwrap();
        assert_eq!(mid.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![3, 4]);

        // from beyond the end → empty.
        let empty = storage.read_stream("t", "a", "s", sh, 99, 10).unwrap();
        assert!(empty.is_empty());

        // tail of 2 → last two seqs present.
        let tail = storage.read_tail("t", "a", "s", sh, 2).unwrap();
        let seqs: Vec<u64> = tail.iter().map(|e| e.seq).collect();
        assert!(seqs.contains(&5) && seqs.contains(&4), "tail has latest: {seqs:?}");
    }

    #[test]
    fn force_seal_head_on_empty_head_is_noop_and_reads_resolve() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());
        let sh = corecrux_frame::stream_hash_xxhash64("t", "a", "s").unwrap();
        append_n(&mut storage, sh, "t", "a", "s", 3);

        // Default options seal each append into its own segment, so the head is
        // already empty — force_seal_head is a no-op (sealed=false), not an error.
        let sealed = storage.force_seal_head().expect("seal call ok");
        assert!(!sealed.sealed, "empty head seals to nothing");
        // Reads still resolve across the sealed segments.
        let all = storage.read_stream("t", "a", "s", sh, 1, 0).unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn replay_from_walks_all_frames() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());
        let sh = corecrux_frame::stream_hash_xxhash64("t", "a", "s").unwrap();
        append_n(&mut storage, sh, "t", "a", "s", 4);
        storage.force_seal_head().expect("seal");

        let (frames, _cursor) = storage.replay_from(None, 0).expect("replay");
        assert!(frames.len() >= 4, "replay surfaces all appended frames");
    }

    #[test]
    fn tombstoned_stream_rejects_append() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());
        let sh = corecrux_frame::stream_hash_xxhash64("t", "a", "s").unwrap();
        append_n(&mut storage, sh, "t", "a", "s", 2);
        // Tombstone at seq 5 (monotonic).
        let (_min, tomb) = storage.update_stream_meta(sh, 0, 5).expect("tombstone");
        assert_eq!(tomb, 5);
        let err = storage
            .append_batch(sh, 0, "t", "a", "s", "2026-06-17T00:00:09Z", &[ev("post", b"x")])
            .expect_err("tombstoned");
        match err {
            StorageError::FailedPrecondition { code, .. } => assert_eq!(code, "STREAM_TOMBSTONED"),
            other => panic!("unexpected: {other}"),
        }
    }
}
