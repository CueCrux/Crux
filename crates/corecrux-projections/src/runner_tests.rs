// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Integration tests for the projection runner — builds synthetic segments and asserts replay/snapshot round-trips.

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::Path;

    use corecrux_frame::{
        canonical_header_bytes_v1, compute_header_hash, compute_payload_hash, stream_hash_xxhash64, CanonicalHeaderV1,
    };
    use corecrux_segment::{build_segment_v1, SegmentId};
    use corecrux_storage::{
        encode_manifest_add_segment_v1, encode_manifest_header_v1, frame_manifest_record, SegmentMeta, ShardPaths,
        ShardStorage, ShardStorageOptions,
    };
    use uuid::Uuid;

    use crate::ccxs::CcxsSnapshot;
    use crate::ccxs::CCXS_BLOCK_COLD_SEGMENT_DIR_V1;
    use crate::ccxs::CCXS_BLOCK_HOT_PTRS_V1;
    use crate::codec_v1::decode_hot_ptrs_v1;
    use crate::cold_segment_v1::{
        cold_segment_path_v1, decode_cold_segment_dir_v1, read_and_verify_cold_segment_index_v1,
        read_cold_segment_block_v1,
    };
    use crate::events::{
        DependentEvidenceUpsertV1, LivingStateUpdateV1, PressureEventUpsertV1, RelationUpsertV1,
        CONTENT_TYPE_PROJ_BIN_V1, EVT_DEPENDENT_EVIDENCE_UPSERT_V1, EVT_LIVING_STATE_UPDATE_V1, EVT_PRESSURE_UPSERT_V1,
        EVT_RELATION_UPSERT_V1,
    };

    fn make_frame(
        tenant_id: &str,
        artifact_id: u32,
        seq: u64,
        event_id: &'static str,
        event_type: &str,
        content_type: &str,
        payload: &[u8],
    ) -> corecrux_segment::FrameInput<'static> {
        let stream_type = "artifact";
        let stream_id = artifact_id.to_string();
        let stream_hash = stream_hash_xxhash64(tenant_id, stream_type, &stream_id).unwrap();
        let payload_hash = compute_payload_hash(payload);
        let canon = CanonicalHeaderV1 {
            tenant_id: tenant_id.to_string(),
            stream_id,
            stream_type: stream_type.to_string(),
            seq,
            event_id: event_id.to_string(),
            occurred_at: "2026-02-06T00:00:00Z".to_string(),
            ingested_at: "2026-02-06T00:00:00Z".to_string(),
            event_type: event_type.to_string(),
            content_type: content_type.to_string(),
            payload_len: payload.len() as u32,
            payload_hash,
        };
        let canonical_bytes = canonical_header_bytes_v1(&canon);
        let header_hash = compute_header_hash(&canonical_bytes);
        let mut header_bytes = canonical_bytes.clone();
        header_bytes.extend_from_slice(&header_hash);

        // Leak for tests; this keeps FrameInput lifetimes simple.
        let header_bytes: &'static [u8] = Box::leak(header_bytes.into_boxed_slice());
        let payload_bytes: &'static [u8] = Box::leak(payload.to_vec().into_boxed_slice());

        corecrux_segment::FrameInput {
            stream_hash,
            seq,
            event_id,
            header_hash,
            payload_hash,
            header_bytes,
            payload_bytes,
        }
    }

    fn build_storage_with_segments(
        segments: Vec<Vec<corecrux_segment::FrameInput<'static>>>,
    ) -> (tempfile::TempDir, ShardStorage) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let shard_id = 1u32;
        let epoch = 1u64;
        let paths = ShardPaths::for_root(root, shard_id);
        std::fs::create_dir_all(&paths.segments_dir).unwrap();

        // Write segments and a MANIFEST that references them.
        let mut mf = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&paths.manifest_path)
            .unwrap();
        let hdr = encode_manifest_header_v1(shard_id, epoch, /*created_at_unix_ns=*/ 123).unwrap();
        mf.write_all(&hdr).unwrap();

        let mut seg_seq = 1u64;
        for frames in segments {
            let seg_id = SegmentId(*Uuid::new_v4().as_bytes());
            let built = build_segment_v1(
                shard_id, epoch, seg_seq, seg_id, /*created_at_unix_ns=*/ 123, /*sealed_at_unix_ns=*/ 124,
                &frames,
            )
            .unwrap();
            let name = format!("seg-{seg_seq:08}.ccxseg");
            let rel = format!("segments/{name}");
            let dst = paths.segments_dir.join(&name);
            std::fs::write(&dst, &built.bytes).unwrap();

            let seg_meta = SegmentMeta {
                level: 0,
                shard_id,
                epoch,
                segment_seq: seg_seq,
                segment_id: seg_id,
                relative_path: rel,
                file_len: built.footer.file_len,
                created_at_unix_ns: built.footer.created_at_unix_ns,
                sealed_at_unix_ns: built.footer.sealed_at_unix_ns,
                toc_offset: built.footer.toc_offset,
                toc_len: built.footer.toc_len,
                toc_entry_count: built.footer.toc_entry_count,
                min_stream_hash: built.footer.min_stream_hash,
                min_seq: built.footer.min_seq,
                max_stream_hash: built.footer.max_stream_hash,
                max_seq: built.footer.max_seq,
                segment_hash: built.footer.segment_hash,
            };
            let rec = encode_manifest_add_segment_v1(&seg_meta).unwrap();
            mf.write_all(&frame_manifest_record(&rec)).unwrap();
            seg_seq += 1;
        }
        mf.sync_all().unwrap();

        let storage = ShardStorage::open(root, shard_id, epoch, ShardStorageOptions::default()).unwrap();

        (dir, storage)
    }

    #[test]
    fn projections_rebuild_is_microbatch_boundary_invariant() {
        let tenant_id = "tenant-a";

        let living = LivingStateUpdateV1 {
            fields_mask: LivingStateUpdateV1::MASK_LIVING_STATUS
                | LivingStateUpdateV1::MASK_CONFIDENCE
                | LivingStateUpdateV1::MASK_TRUNK_TIER
                | LivingStateUpdateV1::MASK_UPDATED_AT,
            artifact_id: 1,
            living_status: 1, // active
            confidence_q16: 40000,
            last_validated_at_micros: 0,
            next_review_at_micros: 0,
            trunk_tier: 2,
            updated_at_micros: 10,
        };

        let rel = RelationUpsertV1 {
            src_artifact_id: 1,
            dst_artifact_id: 2,
            relation_type: 0, // supports
            confidence_q16: 50000,
            evidence_ref_hash16: [7u8; 16],
            created_at_micros: 10,
            updated_at_micros: 11,
        };

        let dep = DependentEvidenceUpsertV1 {
            artifact_id: 1,
            dependent_type: 0, // answer
            dependent_id: Uuid::parse_str("00000000-0000-0000-0000-0000000000aa").unwrap(),
            last_seen_at_micros: 22,
            usage_weight_q16: 123,
        };

        let pressure = PressureEventUpsertV1 {
            artifact_id: 1,
            pressure_event_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            pressure_code_id: crate::pressure_code_id_xxhash16("COST_PRESSURE"),
            severity: 3,
            observed_at_micros: 30,
            acknowledged_at_micros: 0,
            resolved_at_micros: 0,
            receipt_id: None,
        };

        let frames = vec![
            make_frame(
                tenant_id,
                1,
                1,
                "evt-1",
                EVT_LIVING_STATE_UPDATE_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &living.encode_bin(),
            ),
            make_frame(
                tenant_id,
                1,
                2,
                "evt-2",
                EVT_RELATION_UPSERT_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &rel.encode_bin(),
            ),
            make_frame(
                tenant_id,
                1,
                3,
                "evt-3",
                EVT_DEPENDENT_EVIDENCE_UPSERT_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &dep.encode_bin(),
            ),
            make_frame(
                tenant_id,
                1,
                4,
                "evt-4",
                EVT_PRESSURE_UPSERT_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &pressure.encode_bin(),
            ),
        ];

        let (dir_a, storage_a) = build_storage_with_segments(vec![frames.clone()]);
        let shard_dir_a = dir_a.path().join("shard-0001");
        let mut proj_a = crate::ProjectionStoreV1::load_or_init(&shard_dir_a, 1, 1).unwrap();
        let _ = proj_a.rebuild_from_genesis(&storage_a, /*batch_frames=*/ 1).unwrap();
        let living_a = std::fs::read(&proj_a.files.living_snapshot_path).unwrap();
        let living_hash_a = CcxsSnapshot::snapshot_blake3_hex(&living_a);
        let relations_a = std::fs::read(&proj_a.files.relations_snapshot_path).unwrap();
        let relations_hash_a = CcxsSnapshot::snapshot_blake3_hex(&relations_a);
        let dependents_a = std::fs::read(&proj_a.files.dependents_snapshot_path).unwrap();
        let dependents_hash_a = CcxsSnapshot::snapshot_blake3_hex(&dependents_a);

        let cold_rel_files_a = collect_cold_files(&proj_a.files.cold_relations_dir);
        let cold_dep_files_a = collect_cold_files(&proj_a.files.cold_dependents_dir);

        let (dir_b, storage_b) = build_storage_with_segments(vec![frames]);
        let shard_dir_b = dir_b.path().join("shard-0001");
        let mut proj_b = crate::ProjectionStoreV1::load_or_init(&shard_dir_b, 1, 1).unwrap();
        let _ = proj_b.rebuild_from_genesis(&storage_b, /*batch_frames=*/ 1024).unwrap();
        let living_b = std::fs::read(&proj_b.files.living_snapshot_path).unwrap();
        let living_hash_b = CcxsSnapshot::snapshot_blake3_hex(&living_b);
        let relations_b = std::fs::read(&proj_b.files.relations_snapshot_path).unwrap();
        let relations_hash_b = CcxsSnapshot::snapshot_blake3_hex(&relations_b);
        let dependents_b = std::fs::read(&proj_b.files.dependents_snapshot_path).unwrap();
        let dependents_hash_b = CcxsSnapshot::snapshot_blake3_hex(&dependents_b);

        let cold_rel_files_b = collect_cold_files(&proj_b.files.cold_relations_dir);
        let cold_dep_files_b = collect_cold_files(&proj_b.files.cold_dependents_dir);

        assert_eq!(living_hash_a, living_hash_b);
        assert_eq!(relations_hash_a, relations_hash_b);
        assert_eq!(dependents_hash_a, dependents_hash_b);
        assert_eq!(cold_rel_files_a, cold_rel_files_b);
        assert_eq!(cold_dep_files_a, cold_dep_files_b);

        // Basic sanity: hot pointer blocks reference existing cold blocks.
        assert_hot_ptrs_resolve(&proj_b.files.cold_relations_segments_dir, &relations_b);
        assert_hot_ptrs_resolve(&proj_b.files.cold_dependents_segments_dir, &dependents_b);
    }

    #[test]
    fn projections_rebuild_is_segment_boundary_invariant_for_state() {
        let tenant_id = "tenant-a";

        let living = LivingStateUpdateV1 {
            fields_mask: LivingStateUpdateV1::MASK_LIVING_STATUS
                | LivingStateUpdateV1::MASK_CONFIDENCE
                | LivingStateUpdateV1::MASK_TRUNK_TIER
                | LivingStateUpdateV1::MASK_UPDATED_AT,
            artifact_id: 1,
            living_status: 1, // active
            confidence_q16: 40000,
            last_validated_at_micros: 0,
            next_review_at_micros: 0,
            trunk_tier: 2,
            updated_at_micros: 10,
        };

        let rel = RelationUpsertV1 {
            src_artifact_id: 1,
            dst_artifact_id: 2,
            relation_type: 0, // supports
            confidence_q16: 50000,
            evidence_ref_hash16: [7u8; 16],
            created_at_micros: 10,
            updated_at_micros: 11,
        };

        let frames = vec![
            make_frame(
                tenant_id,
                1,
                1,
                "evt-1",
                EVT_LIVING_STATE_UPDATE_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &living.encode_bin(),
            ),
            make_frame(
                tenant_id,
                1,
                2,
                "evt-2",
                EVT_RELATION_UPSERT_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &rel.encode_bin(),
            ),
        ];

        // Run A: one segment.
        let (dir_a, storage_a) = build_storage_with_segments(vec![frames.clone()]);
        let shard_dir_a = dir_a.path().join("shard-0001");
        let mut proj_a = crate::ProjectionStoreV1::load_or_init(&shard_dir_a, 1, 1).unwrap();
        let _ = proj_a.rebuild_from_genesis(&storage_a, /*batch_frames=*/ 1024).unwrap();

        // Run B: two segments split.
        let seg1 = vec![frames[0].clone()];
        let seg2 = vec![frames[1].clone()];
        let (dir_b, storage_b) = build_storage_with_segments(vec![seg1, seg2]);
        let shard_dir_b = dir_b.path().join("shard-0001");
        let mut proj_b = crate::ProjectionStoreV1::load_or_init(&shard_dir_b, 1, 1).unwrap();
        let _ = proj_b.rebuild_from_genesis(&storage_b, /*batch_frames=*/ 1024).unwrap();

        // Compare decoded state (not snapshot bytes), since cursor differs by segment layout.
        assert_eq!(proj_a.state.living, proj_b.state.living);
        assert_eq!(proj_a.state.relations, proj_b.state.relations);
    }

    fn collect_cold_files(dir: &Path) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        collect_cold_files_inner(dir, dir, &mut out);
        out
    }

    fn collect_cold_files_inner(root: &Path, cur: &Path, out: &mut BTreeSet<String>) {
        let Ok(rd) = std::fs::read_dir(cur) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                collect_cold_files_inner(root, &p, out);
                continue;
            }
            if !p.is_file() {
                continue;
            }
            if let Ok(rel) = p.strip_prefix(root) {
                out.insert(rel.display().to_string());
            }
        }
    }

    // ---- tick() tests ----

    #[test]
    fn tick_returns_none_on_empty_storage() {
        let dir = tempfile::tempdir().unwrap();
        let (dir_a, storage) = build_storage_with_segments(vec![]);
        let shard_dir = dir_a.path().join("shard-0001");
        let mut proj = crate::ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        let result = proj.tick(&storage, 1024).unwrap();
        assert!(result.is_none());
        drop(dir);
    }

    #[test]
    fn tick_processes_living_state_update() {
        let tenant_id = "tenant-tick";
        let living = LivingStateUpdateV1 {
            fields_mask: LivingStateUpdateV1::MASK_LIVING_STATUS
                | LivingStateUpdateV1::MASK_CONFIDENCE
                | LivingStateUpdateV1::MASK_UPDATED_AT,
            artifact_id: 10,
            living_status: 1,
            confidence_q16: 55000,
            last_validated_at_micros: 0,
            next_review_at_micros: 0,
            trunk_tier: 0,
            updated_at_micros: 500,
        };

        let frames = vec![make_frame(
            tenant_id,
            10,
            1,
            "evt-tick-1",
            EVT_LIVING_STATE_UPDATE_V1,
            CONTENT_TYPE_PROJ_BIN_V1,
            &living.encode_bin(),
        )];

        let (dir_a, storage) = build_storage_with_segments(vec![frames]);
        let shard_dir = dir_a.path().join("shard-0001");
        let mut proj = crate::ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        let result = proj.tick(&storage, 1024).unwrap();
        assert!(result.is_some());

        let tick_result = result.unwrap();
        assert_eq!(tick_result.frames_processed, 1);
        assert_eq!(tick_result.state_counts.living_rows, 1);
        assert!(tick_result.cursor_before.is_none());
        assert!(tick_result.cursor_after.is_some());
        assert_eq!(tick_result.commit_id, 1);
        assert_eq!(proj.meta.projection_module_registry.len(), 4);
        assert!(proj.meta.artifact_living_state.module.is_some());
        assert!(proj.meta.artifact_relations.module.is_some());
        assert!(proj.meta.pressure_events.module.is_some());
        assert!(proj.meta.artifact_dependents.module.is_some());
    }

    #[test]
    fn tick_processes_all_event_types() {
        let tenant_id = "tenant-all-types";
        let living = LivingStateUpdateV1 {
            fields_mask: LivingStateUpdateV1::MASK_LIVING_STATUS
                | LivingStateUpdateV1::MASK_CONFIDENCE
                | LivingStateUpdateV1::MASK_TRUNK_TIER
                | LivingStateUpdateV1::MASK_UPDATED_AT,
            artifact_id: 1,
            living_status: 1,
            confidence_q16: 40000,
            last_validated_at_micros: 0,
            next_review_at_micros: 0,
            trunk_tier: 2,
            updated_at_micros: 10,
        };
        let rel = RelationUpsertV1 {
            src_artifact_id: 1,
            dst_artifact_id: 2,
            relation_type: 0,
            confidence_q16: 50000,
            evidence_ref_hash16: [7u8; 16],
            created_at_micros: 10,
            updated_at_micros: 11,
        };
        let dep = DependentEvidenceUpsertV1 {
            artifact_id: 1,
            dependent_type: 0,
            dependent_id: Uuid::parse_str("00000000-0000-0000-0000-0000000000aa").unwrap(),
            last_seen_at_micros: 22,
            usage_weight_q16: 123,
        };
        let pressure = PressureEventUpsertV1 {
            artifact_id: 1,
            pressure_event_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            pressure_code_id: crate::pressure_code_id_xxhash16("COST_PRESSURE"),
            severity: 3,
            observed_at_micros: 30,
            acknowledged_at_micros: 0,
            resolved_at_micros: 0,
            receipt_id: None,
        };

        let frames = vec![
            make_frame(
                tenant_id,
                1,
                1,
                "evt-a1",
                EVT_LIVING_STATE_UPDATE_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &living.encode_bin(),
            ),
            make_frame(
                tenant_id,
                1,
                2,
                "evt-a2",
                EVT_RELATION_UPSERT_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &rel.encode_bin(),
            ),
            make_frame(
                tenant_id,
                1,
                3,
                "evt-a3",
                EVT_DEPENDENT_EVIDENCE_UPSERT_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &dep.encode_bin(),
            ),
            make_frame(
                tenant_id,
                1,
                4,
                "evt-a4",
                EVT_PRESSURE_UPSERT_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &pressure.encode_bin(),
            ),
        ];

        let (dir_a, storage) = build_storage_with_segments(vec![frames]);
        let shard_dir = dir_a.path().join("shard-0001");
        let mut proj = crate::ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        let result = proj.tick(&storage, 1024).unwrap().unwrap();

        assert_eq!(result.frames_processed, 4);
        assert_eq!(result.state_counts.living_rows, 2); // artifact 1 + artifact 2 (from relation)
        assert_eq!(result.state_counts.relations_edges, 1);
        assert_eq!(result.state_counts.dependents_edges, 1);
        assert_eq!(result.state_counts.pressure_rows, 1);
    }

    #[test]
    fn tick_increments_commit_id() {
        let tenant_id = "tenant-commit";
        let living = LivingStateUpdateV1 {
            fields_mask: LivingStateUpdateV1::MASK_LIVING_STATUS,
            artifact_id: 1,
            living_status: 1,
            confidence_q16: 0,
            last_validated_at_micros: 0,
            next_review_at_micros: 0,
            trunk_tier: 0,
            updated_at_micros: 0,
        };
        let frames = vec![make_frame(
            tenant_id,
            1,
            1,
            "evt-c1",
            EVT_LIVING_STATE_UPDATE_V1,
            CONTENT_TYPE_PROJ_BIN_V1,
            &living.encode_bin(),
        )];

        let (dir_a, storage) = build_storage_with_segments(vec![frames]);
        let shard_dir = dir_a.path().join("shard-0001");
        let mut proj = crate::ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();

        let r1 = proj.tick(&storage, 1024).unwrap().unwrap();
        assert_eq!(r1.commit_id, 1);

        // Second tick should return None (no new frames).
        let r2 = proj.tick(&storage, 1024).unwrap();
        assert!(r2.is_none());
    }

    #[test]
    fn tick_updates_cursor() {
        let tenant_id = "tenant-cursor";
        let living = LivingStateUpdateV1 {
            fields_mask: LivingStateUpdateV1::MASK_LIVING_STATUS | LivingStateUpdateV1::MASK_UPDATED_AT,
            artifact_id: 5,
            living_status: 2,
            confidence_q16: 0,
            last_validated_at_micros: 0,
            next_review_at_micros: 0,
            trunk_tier: 0,
            updated_at_micros: 100,
        };
        let frames = vec![make_frame(
            tenant_id,
            5,
            1,
            "evt-cur1",
            EVT_LIVING_STATE_UPDATE_V1,
            CONTENT_TYPE_PROJ_BIN_V1,
            &living.encode_bin(),
        )];

        let (dir_a, storage) = build_storage_with_segments(vec![frames]);
        let shard_dir = dir_a.path().join("shard-0001");
        let mut proj = crate::ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();

        let result = proj.tick(&storage, 1024).unwrap().unwrap();
        assert!(result.cursor_before.is_none());
        let cursor_after = result.cursor_after.unwrap();
        assert_eq!(cursor_after.shard_id, 1);
        assert_eq!(cursor_after.epoch, 1);
        assert!(cursor_after.offset > 0);
    }

    // ---- State query tests ----

    #[test]
    fn state_living_update_partial_mask() {
        // Only update living_status, leave other fields at default.
        let mut state = crate::state::ProjectionState::default();
        let tenant_hash = crate::state::tenant_hash_xxhash64("t1");
        let ev = crate::events::ProjectionEventV1::LivingStateUpdate(LivingStateUpdateV1 {
            fields_mask: LivingStateUpdateV1::MASK_LIVING_STATUS,
            artifact_id: 1,
            living_status: 1,      // active
            confidence_q16: 65535, // should be ignored (not in mask)
            last_validated_at_micros: 0,
            next_review_at_micros: 0,
            trunk_tier: 99, // should be ignored
            updated_at_micros: 0,
        });
        let stats = state.apply(tenant_hash, ev);
        assert_eq!(stats.living_updates, 1);

        let row = state.living.get(&(tenant_hash, 1)).unwrap();
        assert_eq!(row.living_status, crate::state::LivingStatusV1::Active);
        assert_eq!(row.confidence_q16, 0); // Not updated (not in mask).
        assert_eq!(row.trunk_tier, 0); // Not updated.
    }

    #[test]
    fn state_relation_delete_removes_edge() {
        let mut state = crate::state::ProjectionState::default();
        let tenant_hash = crate::state::tenant_hash_xxhash64("t2");

        // Insert a relation.
        state.apply(
            tenant_hash,
            crate::events::ProjectionEventV1::RelationUpsert(RelationUpsertV1 {
                src_artifact_id: 1,
                dst_artifact_id: 2,
                relation_type: 0,
                confidence_q16: 1000,
                evidence_ref_hash16: [0; 16],
                created_at_micros: 0,
                updated_at_micros: 0,
            }),
        );
        assert_eq!(state.relations.len(), 1);

        // Delete it.
        state.apply(
            tenant_hash,
            crate::events::ProjectionEventV1::RelationDelete(crate::events::RelationDeleteV1 {
                src_artifact_id: 1,
                dst_artifact_id: 2,
                relation_type: 0,
            }),
        );
        assert!(state.relations.is_empty());
    }

    #[test]
    fn state_dependent_upsert_max_merge() {
        let mut state = crate::state::ProjectionState::default();
        let tenant_hash = crate::state::tenant_hash_xxhash64("t3");
        let dep_id = Uuid::parse_str("aaaa0000-0000-0000-0000-000000000001").unwrap();

        // First upsert.
        state.apply(
            tenant_hash,
            crate::events::ProjectionEventV1::DependentEvidenceUpsert(DependentEvidenceUpsertV1 {
                artifact_id: 1,
                dependent_type: 0,
                dependent_id: dep_id,
                last_seen_at_micros: 100,
                usage_weight_q16: 50,
            }),
        );

        // Second upsert with lower values (should keep max).
        state.apply(
            tenant_hash,
            crate::events::ProjectionEventV1::DependentEvidenceUpsert(DependentEvidenceUpsertV1 {
                artifact_id: 1,
                dependent_type: 0,
                dependent_id: dep_id,
                last_seen_at_micros: 50,
                usage_weight_q16: 30,
            }),
        );

        let edge = state.dependents.get(&(tenant_hash, 1, 0, dep_id)).unwrap();
        assert_eq!(edge.last_seen_at_micros, 100); // max(100, 50)
        assert_eq!(edge.usage_weight_q16, 50); // max(50, 30)
    }

    #[test]
    fn state_recompute_derived_fields_counts() {
        let mut state = crate::state::ProjectionState::default();
        let th = crate::state::tenant_hash_xxhash64("t4");

        // Add a relation (src=1 -> dst=2).
        state.apply(
            th,
            crate::events::ProjectionEventV1::RelationUpsert(RelationUpsertV1 {
                src_artifact_id: 1,
                dst_artifact_id: 2,
                relation_type: 0,
                confidence_q16: 1000,
                evidence_ref_hash16: [0; 16],
                created_at_micros: 0,
                updated_at_micros: 0,
            }),
        );

        // Add a dependent for artifact 1.
        state.apply(
            th,
            crate::events::ProjectionEventV1::DependentEvidenceUpsert(DependentEvidenceUpsertV1 {
                artifact_id: 1,
                dependent_type: 0,
                dependent_id: Uuid::nil(),
                last_seen_at_micros: 0,
                usage_weight_q16: 0,
            }),
        );

        state.recompute_derived_fields();

        let row1 = state.living.get(&(th, 1)).unwrap();
        assert_eq!(row1.relations_out_count, 1);
        assert_eq!(row1.relations_in_count, 0);
        assert_eq!(row1.dependents_count, 1);

        let row2 = state.living.get(&(th, 2)).unwrap();
        assert_eq!(row2.relations_out_count, 0);
        assert_eq!(row2.relations_in_count, 1);
        assert_eq!(row2.dependents_count, 0);
    }

    #[test]
    fn state_entity_fact_applies_all_three_projections() {
        let mut state = crate::state::ProjectionState::default();
        let th = crate::state::tenant_hash_xxhash64("t5");

        let fact = crate::events::EntityFactV1 {
            tenant_id: "t5".to_string(),
            entity_type: "Person".to_string(),
            entity_name: "Alice".to_string(),
            predicate: "visited".to_string(),
            object_value: "London".to_string(),
            session_id: "s1".to_string(),
            occurred_at_micros: 1000,
            confidence_q16: 50000,
        };
        let stats = state.apply(th, crate::events::ProjectionEventV1::EntityFact(fact));
        assert_eq!(stats.entity_facts, 1);

        // entity_counts should have 1 entity.
        assert_eq!(state.entity_counts.len(), 1);
        let count_row = state.entity_counts.values().next().unwrap();
        assert_eq!(count_row.items.len(), 1);
        assert!(count_row.items.contains("Alice"));

        // entity_timelines should have 1 entry.
        assert_eq!(state.entity_timelines.len(), 1);
        let timeline = state.entity_timelines.values().next().unwrap();
        assert_eq!(timeline.len(), 1);

        // entity_current_state should have 1 entry.
        assert_eq!(state.entity_current_state.len(), 1);
        let cur = state.entity_current_state.values().next().unwrap();
        assert_eq!(cur.current_value, "London");
        assert!(cur.previous_value.is_none());
    }

    #[test]
    fn state_entity_fact_latest_wins() {
        let mut state = crate::state::ProjectionState::default();
        let th = crate::state::tenant_hash_xxhash64("t6");

        let fact1 = crate::events::EntityFactV1 {
            tenant_id: "t6".to_string(),
            entity_type: "Person".to_string(),
            entity_name: "Bob".to_string(),
            predicate: "lives_in".to_string(),
            object_value: "Paris".to_string(),
            session_id: "s1".to_string(),
            occurred_at_micros: 1000,
            confidence_q16: 50000,
        };
        state.apply(th, crate::events::ProjectionEventV1::EntityFact(fact1));

        let fact2 = crate::events::EntityFactV1 {
            tenant_id: "t6".to_string(),
            entity_type: "Person".to_string(),
            entity_name: "Bob".to_string(),
            predicate: "lives_in".to_string(),
            object_value: "Berlin".to_string(),
            session_id: "s2".to_string(),
            occurred_at_micros: 2000,
            confidence_q16: 60000,
        };
        state.apply(th, crate::events::ProjectionEventV1::EntityFact(fact2));

        // Current state should be Berlin (later timestamp).
        let cur = state.entity_current_state.values().next().unwrap();
        assert_eq!(cur.current_value, "Berlin");
        assert_eq!(cur.previous_value.as_deref(), Some("Paris"));
        assert_eq!(cur.previous_occurred_at_micros, 1000);
    }

    #[test]
    fn state_entity_fact_zero_timestamp_skips_timeline() {
        let mut state = crate::state::ProjectionState::default();
        let th = crate::state::tenant_hash_xxhash64("t7");

        let fact = crate::events::EntityFactV1 {
            tenant_id: "t7".to_string(),
            entity_type: "Item".to_string(),
            entity_name: "Guitar".to_string(),
            predicate: "owns".to_string(),
            object_value: "true".to_string(),
            session_id: "s1".to_string(),
            occurred_at_micros: 0,
            confidence_q16: 30000,
        };
        state.apply(th, crate::events::ProjectionEventV1::EntityFact(fact));

        // entity_counts should still have the entity.
        assert_eq!(state.entity_counts.len(), 1);
        // But timeline should be empty (occurred_at_micros == 0).
        assert!(state.entity_timelines.is_empty());
    }

    #[test]
    fn state_pressure_recompute_derived() {
        let mut state = crate::state::ProjectionState::default();
        let th = crate::state::tenant_hash_xxhash64("t-pressure");
        let eid = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();

        // Add unresolved pressure event with severity 4.
        state.apply(
            th,
            crate::events::ProjectionEventV1::PressureUpsert(PressureEventUpsertV1 {
                artifact_id: 1,
                pressure_event_id: eid,
                pressure_code_id: crate::pressure_code_id_xxhash16("TEST_PRESSURE"),
                severity: 4,
                observed_at_micros: 100,
                acknowledged_at_micros: 0,
                resolved_at_micros: 0,
                receipt_id: None,
            }),
        );

        state.recompute_derived_fields();
        let row = state.living.get(&(th, 1)).unwrap();
        assert!(row.pressure_level > 0);
        assert!(row.pressure_reasons_mask != 0);
    }

    #[test]
    fn state_pressure_resolved_does_not_contribute() {
        let mut state = crate::state::ProjectionState::default();
        let th = crate::state::tenant_hash_xxhash64("t-pres-resolved");
        let eid = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();

        // Add a resolved pressure event.
        state.apply(
            th,
            crate::events::ProjectionEventV1::PressureUpsert(PressureEventUpsertV1 {
                artifact_id: 1,
                pressure_event_id: eid,
                pressure_code_id: crate::pressure_code_id_xxhash16("RESOLVED"),
                severity: 5,
                observed_at_micros: 100,
                acknowledged_at_micros: 200,
                resolved_at_micros: 300, // resolved
                receipt_id: None,
            }),
        );

        state.recompute_derived_fields();
        let row = state.living.get(&(th, 1)).unwrap();
        assert_eq!(row.pressure_level, 0);
        assert_eq!(row.pressure_reasons_mask, 0);
    }

    // ---- rebuild_from_genesis ----

    #[test]
    fn rebuild_from_genesis_on_empty_storage() {
        let (dir_a, storage) = build_storage_with_segments(vec![]);
        let shard_dir = dir_a.path().join("shard-0001");
        let mut proj = crate::ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        let result = proj.rebuild_from_genesis(&storage, 1024).unwrap();
        assert_eq!(result.frames_processed, 0);
        assert_eq!(result.state_counts.living_rows, 0);
        assert_eq!(result.state_counts.relations_edges, 0);
        assert_eq!(result.state_counts.dependents_edges, 0);
        assert_eq!(result.state_counts.pressure_rows, 0);
    }

    // ---- quantize/dequantize confidence ----

    #[test]
    fn confidence_quantize_dequantize_roundtrip() {
        for &val in &[0.0f32, 0.5, 1.0, 0.123, 0.999] {
            let q = crate::state::quantize_confidence_q16(val);
            let d = crate::state::dequantize_confidence_f32(q);
            assert!((d - val).abs() < 0.001, "roundtrip failed for {val}: got {d}");
        }
    }

    #[test]
    fn confidence_clamp_out_of_range() {
        assert_eq!(crate::state::quantize_confidence_q16(-1.0), 0);
        assert_eq!(crate::state::quantize_confidence_q16(2.0), 65535);
    }

    // ---- LivingStatusV1 / RelationTypeV1 / DependentTypeV1 helpers ----

    #[test]
    fn living_status_u8_roundtrip() {
        use crate::state::LivingStatusV1;
        for i in 0..=5u8 {
            let s = LivingStatusV1::from_u8(i);
            assert_eq!(s.to_u8(), i);
        }
        // Unknown values map to Dormant.
        assert_eq!(LivingStatusV1::from_u8(255), LivingStatusV1::Dormant);
    }

    #[test]
    fn living_status_engine_str_roundtrip() {
        use crate::state::LivingStatusV1;
        for s in &["dormant", "active", "stale", "contested", "superseded", "deprecated"] {
            let status = LivingStatusV1::from_engine_str(s).unwrap();
            assert_eq!(status.as_engine_str(), *s);
        }
        assert!(LivingStatusV1::from_engine_str("unknown").is_none());
    }

    #[test]
    fn relation_type_u8_roundtrip() {
        use crate::state::RelationTypeV1;
        for i in 0..=11u8 {
            let rt = RelationTypeV1::from_u8(i).unwrap();
            assert_eq!(rt.to_u8(), i);
        }
        assert!(RelationTypeV1::from_u8(12).is_none());
    }

    #[test]
    fn relation_type_engine_str_roundtrip() {
        use crate::state::RelationTypeV1;
        let strs = [
            "supports",
            "contradicts",
            "supersedes",
            "duplicates",
            "elaborates",
            "derived_from",
            "cites",
            "about_same_entity",
            "calls",
            "imports",
            "defines",
            "depends_on",
        ];
        for s in &strs {
            let rt = RelationTypeV1::from_engine_str(s).unwrap();
            assert_eq!(rt.as_engine_str(), *s);
        }
        assert!(RelationTypeV1::from_engine_str("invalid").is_none());
    }

    #[test]
    fn dependent_type_u8_roundtrip() {
        use crate::state::DependentTypeV1;
        for i in 0..=3u8 {
            let dt = DependentTypeV1::from_u8(i).unwrap();
            assert_eq!(dt.to_u8(), i);
        }
        assert!(DependentTypeV1::from_u8(4).is_none());
    }

    #[test]
    fn dependent_type_engine_str_roundtrip() {
        use crate::state::DependentTypeV1;
        for s in &["answer", "mises", "collection", "artifact"] {
            let dt = DependentTypeV1::from_engine_str(s).unwrap();
            assert_eq!(dt.as_engine_str(), *s);
        }
        assert!(DependentTypeV1::from_engine_str("bad").is_none());
    }

    // ---- rebuild_from_genesis with actual data ----

    #[test]
    fn rebuild_from_genesis_produces_cold_segments_and_snapshots() {
        let tenant_id = "tenant-rebuild";
        let living = LivingStateUpdateV1 {
            fields_mask: LivingStateUpdateV1::MASK_LIVING_STATUS
                | LivingStateUpdateV1::MASK_CONFIDENCE
                | LivingStateUpdateV1::MASK_UPDATED_AT,
            artifact_id: 1,
            living_status: 1,
            confidence_q16: 42000,
            last_validated_at_micros: 0,
            next_review_at_micros: 0,
            trunk_tier: 0,
            updated_at_micros: 10,
        };
        let rel = RelationUpsertV1 {
            src_artifact_id: 1,
            dst_artifact_id: 3,
            relation_type: 1,
            confidence_q16: 60000,
            evidence_ref_hash16: [11u8; 16],
            created_at_micros: 20,
            updated_at_micros: 21,
        };
        let dep = DependentEvidenceUpsertV1 {
            artifact_id: 1,
            dependent_type: 1,
            dependent_id: Uuid::parse_str("00000000-0000-0000-0000-0000000000bb").unwrap(),
            last_seen_at_micros: 30,
            usage_weight_q16: 200,
        };
        let pressure = PressureEventUpsertV1 {
            artifact_id: 1,
            pressure_event_id: Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
            pressure_code_id: crate::pressure_code_id_xxhash16("REBUILD_PRESSURE"),
            severity: 2,
            observed_at_micros: 40,
            acknowledged_at_micros: 0,
            resolved_at_micros: 0,
            receipt_id: None,
        };

        let frames = vec![
            make_frame(
                tenant_id,
                1,
                1,
                "evt-rb1",
                EVT_LIVING_STATE_UPDATE_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &living.encode_bin(),
            ),
            make_frame(
                tenant_id,
                1,
                2,
                "evt-rb2",
                EVT_RELATION_UPSERT_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &rel.encode_bin(),
            ),
            make_frame(
                tenant_id,
                1,
                3,
                "evt-rb3",
                EVT_DEPENDENT_EVIDENCE_UPSERT_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &dep.encode_bin(),
            ),
            make_frame(
                tenant_id,
                1,
                4,
                "evt-rb4",
                EVT_PRESSURE_UPSERT_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &pressure.encode_bin(),
            ),
        ];

        let (dir, storage) = build_storage_with_segments(vec![frames]);
        let shard_dir = dir.path().join("shard-0001");
        let mut proj = crate::ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        let result = proj.rebuild_from_genesis(&storage, 1024).unwrap();

        assert_eq!(result.frames_processed, 4);
        assert!(result.state_counts.living_rows >= 1);
        assert_eq!(result.state_counts.relations_edges, 1);
        assert_eq!(result.state_counts.dependents_edges, 1);
        assert_eq!(result.state_counts.pressure_rows, 1);
        assert!(result.cursor_after.is_some());
        assert!(result.cursor_before.is_none());

        // Verify snapshot files exist on disk.
        assert!(proj.files.living_snapshot_path.exists());
        assert!(proj.files.relations_snapshot_path.exists());
        assert!(proj.files.pressure_snapshot_path.exists());
        assert!(proj.files.dependents_snapshot_path.exists());
        assert!(proj.files.meta_path.exists());

        // Verify cold segment directories have content.
        let cold_rel = collect_cold_files(&proj.files.cold_relations_dir);
        assert!(!cold_rel.is_empty(), "cold relations dir should have files");
        let cold_dep = collect_cold_files(&proj.files.cold_dependents_dir);
        assert!(!cold_dep.is_empty(), "cold dependents dir should have files");

        // Verify hot pointers resolve correctly.
        let relations_bytes = std::fs::read(&proj.files.relations_snapshot_path).unwrap();
        assert_hot_ptrs_resolve(&proj.files.cold_relations_segments_dir, &relations_bytes);
        let dependents_bytes = std::fs::read(&proj.files.dependents_snapshot_path).unwrap();
        assert_hot_ptrs_resolve(&proj.files.cold_dependents_segments_dir, &dependents_bytes);
    }

    #[test]
    fn rebuild_from_genesis_batch_size_1_matches_large_batch() {
        let tenant_id = "tenant-batch-cmp";
        let living = LivingStateUpdateV1 {
            fields_mask: LivingStateUpdateV1::MASK_LIVING_STATUS | LivingStateUpdateV1::MASK_UPDATED_AT,
            artifact_id: 5,
            living_status: 2,
            confidence_q16: 0,
            last_validated_at_micros: 0,
            next_review_at_micros: 0,
            trunk_tier: 0,
            updated_at_micros: 100,
        };
        let rel = RelationUpsertV1 {
            src_artifact_id: 5,
            dst_artifact_id: 6,
            relation_type: 2,
            confidence_q16: 30000,
            evidence_ref_hash16: [0u8; 16],
            created_at_micros: 200,
            updated_at_micros: 201,
        };
        let frames = vec![
            make_frame(
                tenant_id,
                5,
                1,
                "evt-bc1",
                EVT_LIVING_STATE_UPDATE_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &living.encode_bin(),
            ),
            make_frame(
                tenant_id,
                5,
                2,
                "evt-bc2",
                EVT_RELATION_UPSERT_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &rel.encode_bin(),
            ),
        ];

        // Batch size 1 (microbatching)
        let (dir_a, storage_a) = build_storage_with_segments(vec![frames.clone()]);
        let shard_dir_a = dir_a.path().join("shard-0001");
        let mut proj_a = crate::ProjectionStoreV1::load_or_init(&shard_dir_a, 1, 1).unwrap();
        let res_a = proj_a.rebuild_from_genesis(&storage_a, 1).unwrap();

        // Large batch
        let (dir_b, storage_b) = build_storage_with_segments(vec![frames]);
        let shard_dir_b = dir_b.path().join("shard-0001");
        let mut proj_b = crate::ProjectionStoreV1::load_or_init(&shard_dir_b, 1, 1).unwrap();
        let res_b = proj_b.rebuild_from_genesis(&storage_b, 1024).unwrap();

        assert_eq!(res_a.frames_processed, res_b.frames_processed);
        assert_eq!(res_a.state_counts.living_rows, res_b.state_counts.living_rows);
        assert_eq!(res_a.state_counts.relations_edges, res_b.state_counts.relations_edges);

        // State must match exactly.
        assert_eq!(proj_a.state.living, proj_b.state.living);
        assert_eq!(proj_a.state.relations, proj_b.state.relations);
    }

    // ---- update_relations_cold_blocks / update_dependents_cold_blocks via tick ----

    #[test]
    fn tick_followed_by_rebuild_produces_same_state() {
        let tenant_id = "tenant-tick-rb";
        let living = LivingStateUpdateV1 {
            fields_mask: LivingStateUpdateV1::MASK_LIVING_STATUS
                | LivingStateUpdateV1::MASK_CONFIDENCE
                | LivingStateUpdateV1::MASK_UPDATED_AT,
            artifact_id: 1,
            living_status: 1,
            confidence_q16: 33000,
            last_validated_at_micros: 0,
            next_review_at_micros: 0,
            trunk_tier: 0,
            updated_at_micros: 10,
        };
        let rel = RelationUpsertV1 {
            src_artifact_id: 1,
            dst_artifact_id: 2,
            relation_type: 0,
            confidence_q16: 44000,
            evidence_ref_hash16: [3u8; 16],
            created_at_micros: 10,
            updated_at_micros: 11,
        };
        let dep = DependentEvidenceUpsertV1 {
            artifact_id: 1,
            dependent_type: 0,
            dependent_id: Uuid::parse_str("00000000-0000-0000-0000-0000000000cc").unwrap(),
            last_seen_at_micros: 22,
            usage_weight_q16: 50,
        };

        let frames = vec![
            make_frame(
                tenant_id,
                1,
                1,
                "evt-tr1",
                EVT_LIVING_STATE_UPDATE_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &living.encode_bin(),
            ),
            make_frame(
                tenant_id,
                1,
                2,
                "evt-tr2",
                EVT_RELATION_UPSERT_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &rel.encode_bin(),
            ),
            make_frame(
                tenant_id,
                1,
                3,
                "evt-tr3",
                EVT_DEPENDENT_EVIDENCE_UPSERT_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &dep.encode_bin(),
            ),
        ];

        // Via tick
        let (dir_a, storage_a) = build_storage_with_segments(vec![frames.clone()]);
        let shard_dir_a = dir_a.path().join("shard-0001");
        let mut proj_a = crate::ProjectionStoreV1::load_or_init(&shard_dir_a, 1, 1).unwrap();
        let _tick = proj_a.tick(&storage_a, 1024).unwrap().unwrap();

        // Via rebuild
        let (dir_b, storage_b) = build_storage_with_segments(vec![frames]);
        let shard_dir_b = dir_b.path().join("shard-0001");
        let mut proj_b = crate::ProjectionStoreV1::load_or_init(&shard_dir_b, 1, 1).unwrap();
        let _rb = proj_b.rebuild_from_genesis(&storage_b, 1024).unwrap();

        // State should match.
        assert_eq!(proj_a.state.living, proj_b.state.living);
        assert_eq!(proj_a.state.relations, proj_b.state.relations);
        assert_eq!(proj_a.state.dependents, proj_b.state.dependents);
        assert_eq!(proj_a.state.pressure, proj_b.state.pressure);
    }

    // ---- cold segment writing exercised through rebuild ----

    #[test]
    fn cold_segments_are_content_addressed_and_verifiable() {
        // Exercises ensure_cold_segment_written + write_cold_segments_for_blocks
        // indirectly through rebuild_from_genesis with relation data.
        let tenant_id = "tenant-cs-verify";
        let rel1 = RelationUpsertV1 {
            src_artifact_id: 10,
            dst_artifact_id: 20,
            relation_type: 0,
            confidence_q16: 30000,
            evidence_ref_hash16: [1u8; 16],
            created_at_micros: 10,
            updated_at_micros: 11,
        };
        let rel2 = RelationUpsertV1 {
            src_artifact_id: 10,
            dst_artifact_id: 30,
            relation_type: 1,
            confidence_q16: 40000,
            evidence_ref_hash16: [2u8; 16],
            created_at_micros: 20,
            updated_at_micros: 21,
        };
        let frames = vec![
            make_frame(
                tenant_id,
                10,
                1,
                "evt-cs1",
                EVT_RELATION_UPSERT_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &rel1.encode_bin(),
            ),
            make_frame(
                tenant_id,
                10,
                2,
                "evt-cs2",
                EVT_RELATION_UPSERT_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &rel2.encode_bin(),
            ),
        ];

        let (dir, storage) = build_storage_with_segments(vec![frames]);
        let shard_dir = dir.path().join("shard-0001");
        let mut proj = crate::ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        let _ = proj.rebuild_from_genesis(&storage, 1024).unwrap();

        // Verify cold segment files exist and are content-addressed (blake3 in filename).
        let cold_files = collect_cold_files(&proj.files.cold_relations_segments_dir);
        assert!(!cold_files.is_empty(), "should have cold segment files");
        for file_rel in &cold_files {
            assert!(
                file_rel.ends_with(".ccxcseg"),
                "cold segments should have .ccxcseg extension"
            );
        }

        // Verify snapshot has valid hot ptrs that resolve to cold segments.
        let relations_bytes = std::fs::read(&proj.files.relations_snapshot_path).unwrap();
        assert_hot_ptrs_resolve(&proj.files.cold_relations_segments_dir, &relations_bytes);
    }

    // ---- ProjectionFilesV1::for_shard_dir ----

    #[test]
    fn projection_files_v1_paths_are_deterministic() {
        let dir = std::path::PathBuf::from("/tmp/test-shard");
        let files = crate::ProjectionFilesV1::for_shard_dir(&dir);
        assert_eq!(files.projections_dir, dir.join("projections"));
        assert_eq!(files.meta_path, dir.join("projections/projections.meta.json"));
        assert!(files
            .living_snapshot_path
            .to_str()
            .unwrap()
            .contains("artifact_living_state"));
        assert!(files
            .relations_snapshot_path
            .to_str()
            .unwrap()
            .contains("artifact_relations"));
        assert!(files
            .pressure_snapshot_path
            .to_str()
            .unwrap()
            .contains("pressure_events"));
        assert!(files
            .dependents_snapshot_path
            .to_str()
            .unwrap()
            .contains("artifact_dependents"));
        assert_eq!(
            files.cold_relations_segments_dir,
            dir.join("projections/cold/relations/segments")
        );
        assert_eq!(
            files.cold_dependents_segments_dir,
            dir.join("projections/cold/dependents/segments")
        );
    }

    // ---- ProjectionsTickResultV1 / ProjectionCountsV1 serde ----

    #[test]
    fn projections_tick_result_serializes_to_json() {
        // Build a tick result by processing real data.
        let tenant_id = "tenant-serde";
        let living = LivingStateUpdateV1 {
            fields_mask: LivingStateUpdateV1::MASK_LIVING_STATUS,
            artifact_id: 1,
            living_status: 1,
            confidence_q16: 0,
            last_validated_at_micros: 0,
            next_review_at_micros: 0,
            trunk_tier: 0,
            updated_at_micros: 0,
        };
        let frames = vec![make_frame(
            tenant_id,
            1,
            1,
            "evt-serde1",
            EVT_LIVING_STATE_UPDATE_V1,
            CONTENT_TYPE_PROJ_BIN_V1,
            &living.encode_bin(),
        )];
        let (dir, storage) = build_storage_with_segments(vec![frames]);
        let shard_dir = dir.path().join("shard-0001");
        let mut proj = crate::ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        let result = proj.tick(&storage, 1024).unwrap().unwrap();

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"frames_processed\":1"));
        assert!(json.contains("\"commit_id\":1"));
        assert!(json.contains("\"living_rows\":"));
    }

    // ---- ColdSegmentGcOptionsV1 / ColdSegmentGcReportV1 ----

    #[test]
    fn cold_segment_gc_options_debug() {
        let opts = crate::ColdSegmentGcOptionsV1 {
            dry_run: true,
            min_age_seconds: 3600,
            max_delete: 10,
        };
        let debug = format!("{:?}", opts);
        assert!(debug.contains("dry_run: true"));
        assert!(debug.contains("min_age_seconds: 3600"));
    }

    // ---- gc_orphan_cold_segments_v1 on fresh store ----

    #[test]
    fn gc_orphan_cold_segments_on_fresh_store() {
        let tenant_id = "tenant-gc";
        let living = LivingStateUpdateV1 {
            fields_mask: LivingStateUpdateV1::MASK_LIVING_STATUS | LivingStateUpdateV1::MASK_UPDATED_AT,
            artifact_id: 1,
            living_status: 1,
            confidence_q16: 0,
            last_validated_at_micros: 0,
            next_review_at_micros: 0,
            trunk_tier: 0,
            updated_at_micros: 10,
        };
        let rel = RelationUpsertV1 {
            src_artifact_id: 1,
            dst_artifact_id: 2,
            relation_type: 0,
            confidence_q16: 40000,
            evidence_ref_hash16: [0u8; 16],
            created_at_micros: 10,
            updated_at_micros: 11,
        };

        let frames = vec![
            make_frame(
                tenant_id,
                1,
                1,
                "evt-gc1",
                EVT_LIVING_STATE_UPDATE_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &living.encode_bin(),
            ),
            make_frame(
                tenant_id,
                1,
                2,
                "evt-gc2",
                EVT_RELATION_UPSERT_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &rel.encode_bin(),
            ),
        ];

        let (dir, storage) = build_storage_with_segments(vec![frames]);
        let shard_dir = dir.path().join("shard-0001");
        let mut proj = crate::ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        let _ = proj.rebuild_from_genesis(&storage, 1024).unwrap();

        // No orphans should exist on a fresh store.
        let report = proj
            .gc_orphan_cold_segments_v1(crate::ColdSegmentGcOptionsV1 {
                dry_run: false,
                min_age_seconds: 0,
                max_delete: 0,
            })
            .unwrap();

        assert_eq!(report.shard_id, 1);
        assert_eq!(report.relations.orphan_segments, 0);
        assert_eq!(report.dependents.orphan_segments, 0);
        assert_eq!(report.relations.deleted_segments, 0);
        assert_eq!(report.dependents.deleted_segments, 0);
    }

    // ---- gc_orphan_cold_segments_v1 dry_run does not delete ----

    #[test]
    fn gc_orphan_cold_segments_dry_run_does_not_delete() {
        let tenant_id = "tenant-gc-dry";
        let rel = RelationUpsertV1 {
            src_artifact_id: 1,
            dst_artifact_id: 2,
            relation_type: 0,
            confidence_q16: 40000,
            evidence_ref_hash16: [0u8; 16],
            created_at_micros: 10,
            updated_at_micros: 11,
        };
        let frames = vec![make_frame(
            tenant_id,
            1,
            1,
            "evt-gcd1",
            EVT_RELATION_UPSERT_V1,
            CONTENT_TYPE_PROJ_BIN_V1,
            &rel.encode_bin(),
        )];

        let (dir, storage) = build_storage_with_segments(vec![frames]);
        let shard_dir = dir.path().join("shard-0001");
        let mut proj = crate::ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        let _ = proj.rebuild_from_genesis(&storage, 1024).unwrap();

        let cold_before = collect_cold_files(&proj.files.cold_relations_segments_dir);
        let report = proj
            .gc_orphan_cold_segments_v1(crate::ColdSegmentGcOptionsV1 {
                dry_run: true,
                min_age_seconds: 0,
                max_delete: 0,
            })
            .unwrap();

        assert!(report.dry_run);
        let cold_after = collect_cold_files(&proj.files.cold_relations_segments_dir);
        assert_eq!(cold_before, cold_after, "dry_run should not delete any files");
    }

    // ---- load_or_init roundtrip: persists meta, reloads state ----

    #[test]
    fn load_or_init_reload_restores_state() {
        let tenant_id = "tenant-reload";
        let living = LivingStateUpdateV1 {
            fields_mask: LivingStateUpdateV1::MASK_LIVING_STATUS
                | LivingStateUpdateV1::MASK_CONFIDENCE
                | LivingStateUpdateV1::MASK_UPDATED_AT,
            artifact_id: 1,
            living_status: 1,
            confidence_q16: 55000,
            last_validated_at_micros: 0,
            next_review_at_micros: 0,
            trunk_tier: 0,
            updated_at_micros: 100,
        };
        let rel = RelationUpsertV1 {
            src_artifact_id: 1,
            dst_artifact_id: 4,
            relation_type: 3,
            confidence_q16: 22000,
            evidence_ref_hash16: [5u8; 16],
            created_at_micros: 100,
            updated_at_micros: 101,
        };

        let frames = vec![
            make_frame(
                tenant_id,
                1,
                1,
                "evt-rl1",
                EVT_LIVING_STATE_UPDATE_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &living.encode_bin(),
            ),
            make_frame(
                tenant_id,
                1,
                2,
                "evt-rl2",
                EVT_RELATION_UPSERT_V1,
                CONTENT_TYPE_PROJ_BIN_V1,
                &rel.encode_bin(),
            ),
        ];

        let (dir, storage) = build_storage_with_segments(vec![frames]);
        let shard_dir = dir.path().join("shard-0001");

        // Build initial state.
        let mut proj1 = crate::ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        let res1 = proj1.rebuild_from_genesis(&storage, 1024).unwrap();
        assert!(res1.state_counts.living_rows >= 1);
        assert_eq!(res1.state_counts.relations_edges, 1);

        // Reload from persisted snapshots.
        let proj2 = crate::ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        assert_eq!(proj1.state.living.len(), proj2.state.living.len());
        assert_eq!(proj1.state.relations.len(), proj2.state.relations.len());
        assert_eq!(proj1.state.dependents.len(), proj2.state.dependents.len());
        assert_eq!(proj1.state.pressure.len(), proj2.state.pressure.len());
    }

    // ---- Multiple ticks process incrementally ----

    #[test]
    fn multiple_ticks_advance_cursor_incrementally() {
        let tenant_id = "tenant-multi-tick";
        let living1 = LivingStateUpdateV1 {
            fields_mask: LivingStateUpdateV1::MASK_LIVING_STATUS,
            artifact_id: 1,
            living_status: 1,
            confidence_q16: 0,
            last_validated_at_micros: 0,
            next_review_at_micros: 0,
            trunk_tier: 0,
            updated_at_micros: 0,
        };
        let living2 = LivingStateUpdateV1 {
            fields_mask: LivingStateUpdateV1::MASK_LIVING_STATUS,
            artifact_id: 2,
            living_status: 1,
            confidence_q16: 0,
            last_validated_at_micros: 0,
            next_review_at_micros: 0,
            trunk_tier: 0,
            updated_at_micros: 0,
        };

        // Two segments, one frame each.
        let seg1 = vec![make_frame(
            tenant_id,
            1,
            1,
            "evt-mt1",
            EVT_LIVING_STATE_UPDATE_V1,
            CONTENT_TYPE_PROJ_BIN_V1,
            &living1.encode_bin(),
        )];
        let seg2 = vec![make_frame(
            tenant_id,
            2,
            1,
            "evt-mt2",
            EVT_LIVING_STATE_UPDATE_V1,
            CONTENT_TYPE_PROJ_BIN_V1,
            &living2.encode_bin(),
        )];

        let (dir, storage) = build_storage_with_segments(vec![seg1, seg2]);
        let shard_dir = dir.path().join("shard-0001");
        let mut proj = crate::ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();

        // First tick: process one frame.
        let r1 = proj.tick(&storage, 1).unwrap().unwrap();
        assert_eq!(r1.frames_processed, 1);
        assert_eq!(r1.commit_id, 1);
        let cursor1 = r1.cursor_after.clone().unwrap();

        // Second tick: process next frame.
        let r2 = proj.tick(&storage, 1).unwrap().unwrap();
        assert_eq!(r2.frames_processed, 1);
        assert_eq!(r2.commit_id, 2);
        let cursor2 = r2.cursor_after.clone().unwrap();
        assert!(
            cursor2.segment_seq > cursor1.segment_seq || cursor2.offset > cursor1.offset,
            "cursor should advance"
        );

        // Third tick: no more data.
        let r3 = proj.tick(&storage, 1024).unwrap();
        assert!(r3.is_none());

        // State should have 2 living rows.
        assert_eq!(proj.state.living.len(), 2);
    }

    // ---- ColdSegmentGcReportV1 serde ----

    #[test]
    fn cold_segment_gc_report_serializes() {
        let report = crate::ColdSegmentGcReportV1 {
            shard_id: 1,
            epoch: 1,
            dry_run: true,
            min_age_seconds: 60,
            max_delete: 5,
            relations: crate::ColdSegmentGcProjectionReportV1 {
                projection: "relations".to_string(),
                schema_version: 3,
                skipped: false,
                skip_reason: None,
                reachable_segments: 2,
                segments_on_disk: 3,
                orphan_segments: 1,
                deleted_segments: 0,
                deleted_bytes: 0,
                skipped_young_segments: 1,
                kept_orphans_due_to_limit: 0,
                unparseable_segment_files: 0,
            },
            dependents: crate::ColdSegmentGcProjectionReportV1 {
                projection: "dependents".to_string(),
                schema_version: 3,
                skipped: true,
                skip_reason: Some("test skip".to_string()),
                reachable_segments: 0,
                segments_on_disk: 0,
                orphan_segments: 0,
                deleted_segments: 0,
                deleted_bytes: 0,
                skipped_young_segments: 0,
                kept_orphans_due_to_limit: 0,
                unparseable_segment_files: 0,
            },
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"shardId\":1"));
        assert!(json.contains("\"schemaVersion\":3"));
        assert!(json.contains("\"test skip\""));
    }

    fn assert_hot_ptrs_resolve(cold_segments_dir: &Path, snapshot_bytes: &[u8]) {
        let snap = CcxsSnapshot::decode(snapshot_bytes).unwrap();
        let Some((_, block)) = snap.blocks.iter().find(|(t, _)| *t == CCXS_BLOCK_HOT_PTRS_V1) else {
            panic!("snapshot missing hot ptr block");
        };
        let Some((_, dir_block)) = snap.blocks.iter().find(|(t, _)| *t == CCXS_BLOCK_COLD_SEGMENT_DIR_V1) else {
            panic!("snapshot missing cold segment dir block");
        };
        let ptrs = decode_hot_ptrs_v1(block).unwrap();
        let dir = decode_cold_segment_dir_v1(dir_block).unwrap();
        assert!(!ptrs.is_empty(), "expected non-empty hot ptrs");

        // Build a mapping from block hash -> segment path + offset/len.
        let mut locs: std::collections::BTreeMap<[u8; 32], (std::path::PathBuf, u64, u32)> =
            std::collections::BTreeMap::new();
        for s in dir {
            let seg_path = cold_segment_path_v1(cold_segments_dir, &s.segment_blake3);
            assert!(seg_path.exists(), "missing cold segment {}", seg_path.display());
            let (_hdr, idx) = read_and_verify_cold_segment_index_v1(&seg_path, &s.segment_blake3, s.file_len).unwrap();
            for it in idx {
                locs.insert(it.block_blake3, (seg_path.clone(), it.offset, it.len));
            }
        }

        for (_key, p) in ptrs {
            let (seg_path, offset, len) = locs
                .get(&p.blake3)
                .unwrap_or_else(|| panic!("missing cold block blake3 {}", blake3::Hash::from(p.blake3).to_hex()))
                .clone();
            assert_eq!(len as usize, p.block_len as usize);
            let bytes = read_cold_segment_block_v1(&seg_path, offset, len).unwrap();
            let actual = blake3::hash(&bytes);
            assert_eq!(
                actual.as_bytes(),
                &p.blake3,
                "block hash mismatch in {}",
                seg_path.display()
            );
        }
    }

    // ── ProjectionFilesV1 path structure ─────────────────────────────

    #[test]
    fn projection_files_cold_dirs_are_nested() {
        use crate::runner::ProjectionFilesV1;
        let files = ProjectionFilesV1::for_shard_dir(Path::new("/data/shard-0001"));
        assert!(files.cold_relations_dir.starts_with(&files.projections_dir));
        assert!(files.cold_dependents_dir.starts_with(&files.projections_dir));
        assert!(files.cold_relations_segments_dir.starts_with(&files.cold_relations_dir));
        assert!(files
            .cold_dependents_segments_dir
            .starts_with(&files.cold_dependents_dir));
    }

    // ── ColdSegmentGcOptionsV1 fields ───────────────────────────────

    #[test]
    fn cold_segment_gc_options_fields() {
        use crate::ColdSegmentGcOptionsV1;
        let opts = ColdSegmentGcOptionsV1 {
            dry_run: true,
            min_age_seconds: 3600,
            max_delete: 100,
        };
        assert!(opts.dry_run);
        assert_eq!(opts.min_age_seconds, 3600);
        assert_eq!(opts.max_delete, 100);
    }

    // ── ColdSegmentGcReportV1 serialization ─────────────────────────

    #[test]
    fn cold_segment_gc_report_serde() {
        use crate::{ColdSegmentGcProjectionReportV1, ColdSegmentGcReportV1};
        let report = ColdSegmentGcReportV1 {
            shard_id: 1,
            epoch: 2,
            dry_run: false,
            min_age_seconds: 0,
            max_delete: 0,
            relations: ColdSegmentGcProjectionReportV1 {
                projection: "relations".to_string(),
                schema_version: 3,
                skipped: false,
                skip_reason: None,
                reachable_segments: 5,
                segments_on_disk: 7,
                orphan_segments: 2,
                deleted_segments: 2,
                deleted_bytes: 1024,
                skipped_young_segments: 0,
                kept_orphans_due_to_limit: 0,
                unparseable_segment_files: 0,
            },
            dependents: ColdSegmentGcProjectionReportV1 {
                projection: "dependents".to_string(),
                schema_version: 3,
                skipped: true,
                skip_reason: Some("test".to_string()),
                reachable_segments: 0,
                segments_on_disk: 3,
                orphan_segments: 0,
                deleted_segments: 0,
                deleted_bytes: 0,
                skipped_young_segments: 0,
                kept_orphans_due_to_limit: 0,
                unparseable_segment_files: 0,
            },
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["shardId"], 1);
        assert_eq!(json["relations"]["reachable_segments"], 5);
        assert_eq!(json["relations"]["deleted_segments"], 2);
        assert_eq!(json["dependents"]["skipped"], true);
    }

    // ── ProjectionsTickResultV1 serialization ───────────────────────

    #[test]
    fn projection_counts_serialize() {
        use crate::runner::{ProjectionCountsV1, ProjectionsTickResultV1};
        let result = ProjectionsTickResultV1 {
            frames_processed: 42,
            cursor_before: None,
            cursor_after: None,
            commit_id: 7,
            state_counts: ProjectionCountsV1 {
                living_rows: 10,
                relations_edges: 5,
                dependents_edges: 3,
                pressure_rows: 1,
            },
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["frames_processed"], 42);
        assert_eq!(json["commit_id"], 7);
        assert_eq!(json["state_counts"]["living_rows"], 10);
    }

    // ── ColdSegmentGcProjectionReportV1 skip_reason serialization ────

    #[test]
    fn gc_projection_report_skip_reason_omitted_when_none() {
        use crate::ColdSegmentGcProjectionReportV1;
        let report = ColdSegmentGcProjectionReportV1 {
            projection: "relations".to_string(),
            schema_version: 3,
            skipped: false,
            skip_reason: None,
            reachable_segments: 0,
            segments_on_disk: 0,
            orphan_segments: 0,
            deleted_segments: 0,
            deleted_bytes: 0,
            skipped_young_segments: 0,
            kept_orphans_due_to_limit: 0,
            unparseable_segment_files: 0,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("skip_reason"));
    }

    // ── rebuild_from_genesis on empty storage ────────────────────────

    #[test]
    fn rebuild_from_genesis_empty_produces_zero_counts() {
        let segments: Vec<Vec<corecrux_segment::FrameInput<'static>>> = vec![];
        let (dir, storage) = build_storage_with_segments(segments);

        let mut proj =
            crate::ProjectionStoreV1::load_or_init(&ShardPaths::for_root(dir.path(), 1).shard_dir, 1, 1).unwrap();
        let r = proj.rebuild_from_genesis(&storage, 100).unwrap();
        assert_eq!(r.frames_processed, 0);
        assert_eq!(r.state_counts.living_rows, 0);
        assert_eq!(r.state_counts.relations_edges, 0);
        assert_eq!(r.state_counts.dependents_edges, 0);
        assert_eq!(r.state_counts.pressure_rows, 0);
    }

    // ── tick on empty storage returns None ───────────────────────────

    #[test]
    fn tick_on_empty_storage_returns_none() {
        let segments: Vec<Vec<corecrux_segment::FrameInput<'static>>> = vec![];
        let (dir, storage) = build_storage_with_segments(segments);

        let mut proj =
            crate::ProjectionStoreV1::load_or_init(&ShardPaths::for_root(dir.path(), 1).shard_dir, 1, 1).unwrap();
        let result = proj.tick(&storage, 100).unwrap();
        assert!(result.is_none());
    }

    // ── gc_orphan_cold_segments on fresh store ──────────────────────

    #[test]
    fn gc_orphan_cold_segments_fresh_store_reports_zero() {
        let segments: Vec<Vec<corecrux_segment::FrameInput<'static>>> = vec![];
        let (dir, _storage) = build_storage_with_segments(segments);

        let mut proj =
            crate::ProjectionStoreV1::load_or_init(&ShardPaths::for_root(dir.path(), 1).shard_dir, 1, 1).unwrap();
        let report = proj
            .gc_orphan_cold_segments_v1(crate::ColdSegmentGcOptionsV1 {
                dry_run: true,
                min_age_seconds: 0,
                max_delete: 0,
            })
            .unwrap();
        assert_eq!(report.relations.segments_on_disk, 0);
        assert_eq!(report.dependents.segments_on_disk, 0);
    }
}
