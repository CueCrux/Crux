// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Projection materialiser: replays sealed-segment frames through Phase 7 event handlers and writes `.ccxsnap` snapshots.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use corecrux_frame::decode_canonical_header_bytes_v1;
use corecrux_segment::decode_frame_v1;
use corecrux_storage::{ReplayCursor, ReplayFrames, ShardStorage};

use crate::ccxsnap::{
    CcxsnapProjectionId, CcxsnapSnapshot, CcxsnapSnapshotHeaderV1, CCXSNAP_BLOCK_COLD_SEGMENT_DIR_V1,
    CCXSNAP_BLOCK_EDGES_V1, CCXSNAP_BLOCK_EVENTS_V1, CCXSNAP_BLOCK_HOT_PTRS_V1, CCXSNAP_BLOCK_ROWS_V1,
    CCXSNAP_CODEC_NONE,
};
use crate::codec_v1::{
    decode_dependents_edges_v1, decode_hot_ptrs_v1, decode_living_rows_v1, decode_pressure_rows_v1,
    decode_relations_edges_v1, encode_dependents_edges_for_artifact_v1, encode_hot_ptrs_v1, encode_living_rows_v1,
    encode_pressure_rows_v1, encode_relations_edges_for_src_v1, HotPtrEntryV1, DEPENDENT_EDGE_STRIDE_V1,
    RELATION_EDGE_STRIDE_V1,
};
use crate::cold_segment_v1::{
    build_cold_segment_v1, cold_segment_path_v1, decode_cold_segment_dir_v1, encode_cold_segment_dir_v1,
    read_and_verify_cold_segment_index_v1, read_cold_segment_block_v1, ColdBlockLocV1, ColdSegmentDirEntryV1,
    ColdSegmentIndexEntryV1,
};
use crate::events::{parse_projection_event, ProjectionEventV1};
use crate::meta::{
    load_projections_meta_v1, record_current_projection_modules_v1, store_projections_meta_v1, ProjectionCursorV1,
};
use crate::state::ProjectionState;
use crate::{ProjectionError, Result};

#[derive(Debug, Clone)]
pub struct ProjectionFilesV1 {
    pub projections_dir: PathBuf,
    pub meta_path: PathBuf,
    pub living_snapshot_path: PathBuf,
    pub relations_snapshot_path: PathBuf,
    pub pressure_snapshot_path: PathBuf,
    pub dependents_snapshot_path: PathBuf,
    pub cold_relations_dir: PathBuf,
    pub cold_relations_segments_dir: PathBuf,
    pub cold_dependents_dir: PathBuf,
    pub cold_dependents_segments_dir: PathBuf,
}

impl ProjectionFilesV1 {
    pub fn for_shard_dir(shard_dir: &Path) -> Self {
        let projections_dir = shard_dir.join("projections");
        let cold_dir = projections_dir.join("cold");
        let cold_relations_dir = cold_dir.join("relations");
        let cold_dependents_dir = cold_dir.join("dependents");
        let cold_relations_segments_dir = cold_relations_dir.join("segments");
        let cold_dependents_segments_dir = cold_dependents_dir.join("segments");
        Self {
            meta_path: projections_dir.join("projections.meta.json"),
            living_snapshot_path: projections_dir.join("artifact_living_state.snapshot.ccxsnap"),
            relations_snapshot_path: projections_dir.join("artifact_relations.snapshot.ccxsnap"),
            pressure_snapshot_path: projections_dir.join("pressure_events.snapshot.ccxsnap"),
            dependents_snapshot_path: projections_dir.join("artifact_dependents.snapshot.ccxsnap"),
            cold_relations_dir,
            cold_relations_segments_dir,
            cold_dependents_dir,
            cold_dependents_segments_dir,
            projections_dir,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProjectionsTickResultV1 {
    pub frames_processed: u64,
    pub cursor_before: Option<ProjectionCursorV1>,
    pub cursor_after: Option<ProjectionCursorV1>,
    pub commit_id: u64,
    pub state_counts: ProjectionCountsV1,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProjectionCountsV1 {
    pub living_rows: u64,
    pub relations_edges: u64,
    pub dependents_edges: u64,
    pub pressure_rows: u64,
}

#[derive(Debug, Clone)]
pub struct ColdSegmentGcOptionsV1 {
    pub dry_run: bool,
    pub min_age_seconds: u64,
    /// Maximum number of orphan segments to delete per projection (0 = unlimited).
    pub max_delete: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ColdSegmentGcProjectionReportV1 {
    pub projection: String,
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub skipped: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,

    pub reachable_segments: u64,
    pub segments_on_disk: u64,
    pub orphan_segments: u64,

    pub deleted_segments: u64,
    pub deleted_bytes: u64,
    pub skipped_young_segments: u64,
    pub kept_orphans_due_to_limit: u64,
    pub unparseable_segment_files: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ColdSegmentGcReportV1 {
    #[serde(rename = "shardId")]
    pub shard_id: u32,
    pub epoch: u64,
    pub dry_run: bool,
    pub min_age_seconds: u64,
    pub max_delete: u64,
    pub relations: ColdSegmentGcProjectionReportV1,
    pub dependents: ColdSegmentGcProjectionReportV1,
}

type ColdSegmentMapsV1 = (BTreeMap<[u8; 32], u64>, BTreeMap<[u8; 32], ColdBlockLocV1>);

pub struct ProjectionStoreV1 {
    pub shard_id: u32,
    pub epoch: u64,
    pub files: ProjectionFilesV1,
    pub meta: crate::meta::ProjectionsMetaV1,
    pub state: ProjectionState,
    pub relations_hot_ptrs: BTreeMap<(u64, u32), HotPtrEntryV1>,
    pub dependents_hot_ptrs: BTreeMap<(u64, u32), HotPtrEntryV1>,
    pub relations_cold_segments: BTreeMap<[u8; 32], u64>, // segment_blake3 -> file_len
    pub dependents_cold_segments: BTreeMap<[u8; 32], u64>, // segment_blake3 -> file_len
    pub relations_block_locs: BTreeMap<[u8; 32], ColdBlockLocV1>, // block_blake3 -> loc
    pub dependents_block_locs: BTreeMap<[u8; 32], ColdBlockLocV1>, // block_blake3 -> loc
}

impl ProjectionStoreV1 {
    pub fn load_or_init(shard_dir: &Path, shard_id: u32, epoch: u64) -> Result<Self> {
        let files = ProjectionFilesV1::for_shard_dir(shard_dir);
        std::fs::create_dir_all(&files.projections_dir)?;
        std::fs::create_dir_all(&files.cold_relations_dir)?;
        std::fs::create_dir_all(&files.cold_relations_segments_dir)?;
        std::fs::create_dir_all(&files.cold_dependents_dir)?;
        std::fs::create_dir_all(&files.cold_dependents_segments_dir)?;

        let mut meta = load_projections_meta_v1(&files.meta_path)?;
        let mut state = ProjectionState::default();
        let mut relations_hot_ptrs: BTreeMap<(u64, u32), HotPtrEntryV1> = BTreeMap::new();
        let mut dependents_hot_ptrs: BTreeMap<(u64, u32), HotPtrEntryV1> = BTreeMap::new();
        let mut relations_cold_segments: BTreeMap<[u8; 32], u64> = BTreeMap::new();
        let mut dependents_cold_segments: BTreeMap<[u8; 32], u64> = BTreeMap::new();
        let mut relations_block_locs: BTreeMap<[u8; 32], ColdBlockLocV1> = BTreeMap::new();
        let mut dependents_block_locs: BTreeMap<[u8; 32], ColdBlockLocV1> = BTreeMap::new();
        let mut ok = true;

        // A snapshot that meta DECLARES but that is absent on disk must reset
        // to genesis exactly as a corrupt one does. The `.filter(|_|
        // …exists())` guards below skip the whole verification block when the
        // file is gone, which left `ok = true`: the store was returned with
        // the cursor intact and the state empty, so the next `tick` resumed
        // past frames it had never applied. A deleted snapshot is silent data
        // loss; it must not read the same as a clean load.
        for (declared, path) in [
            (
                meta.artifact_living_state.snapshot_blake3.is_some(),
                &files.living_snapshot_path,
            ),
            (
                meta.artifact_relations.snapshot_blake3.is_some(),
                &files.relations_snapshot_path,
            ),
            (
                meta.artifact_dependents.snapshot_blake3.is_some(),
                &files.dependents_snapshot_path,
            ),
            (
                meta.pressure_events.snapshot_blake3.is_some(),
                &files.pressure_snapshot_path,
            ),
        ] {
            // This crate carries no logger by design; the genesis reset below
            // is itself the signal, and `tick` re-derives the state.
            if declared && !path.exists() {
                ok = false;
            }
        }

        // Treat meta as source of truth; ignore snapshots whose blake3 doesn't match.
        if let Some(h) = meta
            .artifact_living_state
            .snapshot_blake3
            .as_deref()
            .filter(|_| files.living_snapshot_path.exists())
        {
            match std::fs::read(&files.living_snapshot_path) {
                Ok(bytes) => {
                    if CcxsnapSnapshot::snapshot_blake3_hex(&bytes) == h {
                        match CcxsnapSnapshot::decode(&bytes) {
                            Ok(snap) => {
                                if let Some((_, block)) = snap.blocks.iter().find(|(t, _)| *t == CCXSNAP_BLOCK_ROWS_V1)
                                {
                                    if let Ok(rows) = decode_living_rows_v1(block) {
                                        state.living = rows;
                                    } else {
                                        ok = false;
                                    }
                                } else {
                                    ok = false;
                                }
                            }
                            Err(_) => ok = false,
                        }
                    } else {
                        ok = false;
                    }
                }
                Err(_) => ok = false,
            }
        }
        if let Some(h) = meta
            .artifact_relations
            .snapshot_blake3
            .as_deref()
            .filter(|_| files.relations_snapshot_path.exists())
        {
            match std::fs::read(&files.relations_snapshot_path) {
                Ok(bytes) => {
                    if CcxsnapSnapshot::snapshot_blake3_hex(&bytes) == h {
                        match CcxsnapSnapshot::decode(&bytes) {
                            Ok(snap) => match meta.artifact_relations.schema_version {
                                1 => {
                                    if let Some((_, block)) =
                                        snap.blocks.iter().find(|(t, _)| *t == CCXSNAP_BLOCK_EDGES_V1)
                                    {
                                        if let Ok(edges) = decode_relations_edges_v1(block) {
                                            state.relations = edges;
                                        } else {
                                            ok = false;
                                        }
                                    } else {
                                        ok = false;
                                    }
                                }
                                2 => {
                                    if let Some((_, block)) =
                                        snap.blocks.iter().find(|(t, _)| *t == CCXSNAP_BLOCK_HOT_PTRS_V1)
                                    {
                                        match decode_hot_ptrs_v1(block) {
                                            Ok(ptrs) => {
                                                relations_hot_ptrs = ptrs;
                                                match load_relations_from_cold_blocks(&files, &relations_hot_ptrs) {
                                                    Ok(edges) => state.relations = edges,
                                                    Err(_) => ok = false,
                                                }
                                            }
                                            Err(_) => ok = false,
                                        }
                                    } else {
                                        ok = false;
                                    }
                                }
                                3 => {
                                    if let (Some((_, hot_block)), Some((_, dir_block))) = (
                                        snap.blocks.iter().find(|(t, _)| *t == CCXSNAP_BLOCK_HOT_PTRS_V1),
                                        snap.blocks
                                            .iter()
                                            .find(|(t, _)| *t == CCXSNAP_BLOCK_COLD_SEGMENT_DIR_V1),
                                    ) {
                                        match (decode_hot_ptrs_v1(hot_block), decode_cold_segment_dir_v1(dir_block)) {
                                            (Ok(ptrs), Ok(dir)) => {
                                                relations_hot_ptrs = ptrs;
                                                match load_cold_segment_indexes(
                                                    &files.cold_relations_segments_dir,
                                                    &dir,
                                                ) {
                                                    Ok((segs, locs)) => {
                                                        relations_cold_segments = segs;
                                                        relations_block_locs = locs;
                                                        match load_relations_from_cold_segments(
                                                            &files,
                                                            &relations_hot_ptrs,
                                                            &relations_block_locs,
                                                        ) {
                                                            Ok(edges) => state.relations = edges,
                                                            Err(_) => ok = false,
                                                        }
                                                    }
                                                    Err(_) => ok = false,
                                                }
                                            }
                                            _ => ok = false,
                                        }
                                    } else {
                                        ok = false;
                                    }
                                }
                                other => {
                                    return Err(ProjectionError::InvalidEvent {
                                        msg: format!("unsupported relations schema_version {}", other),
                                    });
                                }
                            },
                            Err(_) => ok = false,
                        }
                    } else {
                        ok = false;
                    }
                }
                Err(_) => ok = false,
            }
        }
        if let Some(h) = meta
            .artifact_dependents
            .snapshot_blake3
            .as_deref()
            .filter(|_| files.dependents_snapshot_path.exists())
        {
            match std::fs::read(&files.dependents_snapshot_path) {
                Ok(bytes) => {
                    if CcxsnapSnapshot::snapshot_blake3_hex(&bytes) == h {
                        match CcxsnapSnapshot::decode(&bytes) {
                            Ok(snap) => match meta.artifact_dependents.schema_version {
                                1 => {
                                    if let Some((_, block)) =
                                        snap.blocks.iter().find(|(t, _)| *t == CCXSNAP_BLOCK_EDGES_V1)
                                    {
                                        if let Ok(edges) = decode_dependents_edges_v1(block) {
                                            state.dependents = edges;
                                        } else {
                                            ok = false;
                                        }
                                    } else {
                                        ok = false;
                                    }
                                }
                                2 => {
                                    if let Some((_, block)) =
                                        snap.blocks.iter().find(|(t, _)| *t == CCXSNAP_BLOCK_HOT_PTRS_V1)
                                    {
                                        match decode_hot_ptrs_v1(block) {
                                            Ok(ptrs) => {
                                                dependents_hot_ptrs = ptrs;
                                                match load_dependents_from_cold_blocks(&files, &dependents_hot_ptrs) {
                                                    Ok(edges) => state.dependents = edges,
                                                    Err(_) => ok = false,
                                                }
                                            }
                                            Err(_) => ok = false,
                                        }
                                    } else {
                                        ok = false;
                                    }
                                }
                                3 => {
                                    if let (Some((_, hot_block)), Some((_, dir_block))) = (
                                        snap.blocks.iter().find(|(t, _)| *t == CCXSNAP_BLOCK_HOT_PTRS_V1),
                                        snap.blocks
                                            .iter()
                                            .find(|(t, _)| *t == CCXSNAP_BLOCK_COLD_SEGMENT_DIR_V1),
                                    ) {
                                        match (decode_hot_ptrs_v1(hot_block), decode_cold_segment_dir_v1(dir_block)) {
                                            (Ok(ptrs), Ok(dir)) => {
                                                dependents_hot_ptrs = ptrs;
                                                match load_cold_segment_indexes(
                                                    &files.cold_dependents_segments_dir,
                                                    &dir,
                                                ) {
                                                    Ok((segs, locs)) => {
                                                        dependents_cold_segments = segs;
                                                        dependents_block_locs = locs;
                                                        match load_dependents_from_cold_segments(
                                                            &files,
                                                            &dependents_hot_ptrs,
                                                            &dependents_block_locs,
                                                        ) {
                                                            Ok(edges) => state.dependents = edges,
                                                            Err(_) => ok = false,
                                                        }
                                                    }
                                                    Err(_) => ok = false,
                                                }
                                            }
                                            _ => ok = false,
                                        }
                                    } else {
                                        ok = false;
                                    }
                                }
                                other => {
                                    return Err(ProjectionError::InvalidEvent {
                                        msg: format!("unsupported dependents schema_version {}", other),
                                    });
                                }
                            },
                            Err(_) => ok = false,
                        }
                    } else {
                        ok = false;
                    }
                }
                Err(_) => ok = false,
            }
        }
        if let Some(h) = meta
            .pressure_events
            .snapshot_blake3
            .as_deref()
            .filter(|_| files.pressure_snapshot_path.exists())
        {
            match std::fs::read(&files.pressure_snapshot_path) {
                Ok(bytes) => {
                    if CcxsnapSnapshot::snapshot_blake3_hex(&bytes) == h {
                        match CcxsnapSnapshot::decode(&bytes) {
                            Ok(snap) => {
                                if let Some((_, block)) =
                                    snap.blocks.iter().find(|(t, _)| *t == CCXSNAP_BLOCK_EVENTS_V1)
                                {
                                    if let Ok(rows) = decode_pressure_rows_v1(block) {
                                        state.pressure = rows;
                                    } else {
                                        ok = false;
                                    }
                                } else {
                                    ok = false;
                                }
                            }
                            Err(_) => ok = false,
                        }
                    } else {
                        ok = false;
                    }
                }
                Err(_) => ok = false,
            }
        }

        if !ok {
            // If any projection snapshot is present but invalid/mismatched, clear meta+state so
            // the next tick replays from genesis deterministically.
            meta = crate::meta::ProjectionsMetaV1::empty_now();
            state = ProjectionState::default();
            relations_hot_ptrs.clear();
            dependents_hot_ptrs.clear();
            relations_cold_segments.clear();
            dependents_cold_segments.clear();
            relations_block_locs.clear();
            dependents_block_locs.clear();
        }

        Ok(Self {
            shard_id,
            epoch,
            files,
            meta,
            state,
            relations_hot_ptrs,
            dependents_hot_ptrs,
            relations_cold_segments,
            dependents_cold_segments,
            relations_block_locs,
            dependents_block_locs,
        })
    }

    fn cursor_from_meta(&self) -> Option<ReplayCursor> {
        self.meta.artifact_living_state.cursor.as_ref().map(|c| ReplayCursor {
            segment_seq: c.segment_seq,
            offset: c.offset,
        })
    }

    fn cursor_v1_from_replay(&self, c: ReplayCursor) -> ProjectionCursorV1 {
        ProjectionCursorV1 {
            shard_id: self.shard_id,
            epoch: self.epoch,
            segment_seq: c.segment_seq,
            offset: c.offset,
        }
    }

    pub fn tick(&mut self, storage: &ShardStorage, max_frames: u32) -> Result<Option<ProjectionsTickResultV1>> {
        let cursor_before = self.meta.artifact_living_state.cursor.clone();
        let (frames, end_cursor) = storage.replay_from_sealed(self.cursor_from_meta(), max_frames)?;
        if frames.is_empty() {
            return Ok(None);
        }

        let mut frames_processed = 0u64;
        let mut touched_relations: BTreeSet<(u64, u32)> = BTreeSet::new();
        let mut touched_dependents: BTreeSet<(u64, u32)> = BTreeSet::new();
        for (_loc, frame_bytes) in &frames {
            frames_processed += 1;
            if let Some((tenant_hash, event_type, content_type, payload_bytes)) =
                decode_frame_projection_inputs(frame_bytes)?
            {
                if let Some(ev) = parse_projection_event(&event_type, &content_type, &payload_bytes)? {
                    match &ev {
                        ProjectionEventV1::RelationUpsert(p) => {
                            touched_relations.insert((tenant_hash, p.src_artifact_id));
                        }
                        ProjectionEventV1::RelationDelete(p) => {
                            touched_relations.insert((tenant_hash, p.src_artifact_id));
                        }
                        ProjectionEventV1::DependentEvidenceUpsert(p) => {
                            touched_dependents.insert((tenant_hash, p.artifact_id));
                        }
                        _ => {}
                    }
                    let _ = self.state.apply(tenant_hash, ev);
                }
            }
        }

        self.state.recompute_derived_fields();

        let cursor_after_replay = end_cursor
            .or_else(|| infer_cursor_after_frames(&frames))
            .map(|c| self.cursor_v1_from_replay(c));
        self.commit(
            storage,
            cursor_after_replay.clone(),
            Some(&touched_relations),
            Some(&touched_dependents),
        )?;

        Ok(Some(ProjectionsTickResultV1 {
            frames_processed,
            cursor_before,
            cursor_after: cursor_after_replay,
            commit_id: self.meta.commit_id,
            state_counts: ProjectionCountsV1 {
                living_rows: self.state.living.len() as u64,
                relations_edges: self.state.relations.len() as u64,
                dependents_edges: self.state.dependents.len() as u64,
                pressure_rows: self.state.pressure.len() as u64,
            },
        }))
    }

    pub fn rebuild_from_genesis(
        &mut self,
        storage: &ShardStorage,
        batch_frames: u32,
    ) -> Result<ProjectionsTickResultV1> {
        self.state = ProjectionState::default();
        self.meta = crate::meta::ProjectionsMetaV1::empty_now();
        self.relations_hot_ptrs.clear();
        self.dependents_hot_ptrs.clear();
        self.relations_cold_segments.clear();
        self.dependents_cold_segments.clear();
        self.relations_block_locs.clear();
        self.dependents_block_locs.clear();
        self.meta.commit_id = 0;
        self.meta.artifact_living_state.cursor = None;
        self.meta.artifact_relations.cursor = None;
        self.meta.pressure_events.cursor = None;
        self.meta.artifact_dependents.cursor = None;

        let mut cursor: Option<ReplayCursor> = None;
        let mut total_frames = 0u64;

        loop {
            let (frames, end_cursor) = storage.replay_from_sealed(cursor, batch_frames)?;
            if frames.is_empty() {
                break;
            }
            for (_loc, frame_bytes) in &frames {
                total_frames += 1;
                if let Some((tenant_hash, event_type, content_type, payload_bytes)) =
                    decode_frame_projection_inputs(frame_bytes)?
                {
                    if let Some(ev) = parse_projection_event(&event_type, &content_type, &payload_bytes)? {
                        let _ = self.state.apply(tenant_hash, ev);
                    }
                }
            }

            cursor = end_cursor.or_else(|| infer_cursor_after_frames(&frames));
            if end_cursor.is_none() {
                // No cursor means we reached end-of-log in this call. Stop.
                break;
            }
        }

        self.state.recompute_derived_fields();
        let cursor_after = cursor.map(|c| self.cursor_v1_from_replay(c));
        self.commit(storage, cursor_after.clone(), None, None)?;

        Ok(ProjectionsTickResultV1 {
            frames_processed: total_frames,
            cursor_before: None,
            cursor_after,
            commit_id: self.meta.commit_id,
            state_counts: ProjectionCountsV1 {
                living_rows: self.state.living.len() as u64,
                relations_edges: self.state.relations.len() as u64,
                dependents_edges: self.state.dependents.len() as u64,
                pressure_rows: self.state.pressure.len() as u64,
            },
        })
    }

    fn commit(
        &mut self,
        storage: &ShardStorage,
        cursor_after: Option<ProjectionCursorV1>,
        touched_relations: Option<&BTreeSet<(u64, u32)>>,
        touched_dependents: Option<&BTreeSet<(u64, u32)>>,
    ) -> Result<()> {
        std::fs::create_dir_all(&self.files.projections_dir)?;
        std::fs::create_dir_all(&self.files.cold_relations_dir)?;
        std::fs::create_dir_all(&self.files.cold_relations_segments_dir)?;
        std::fs::create_dir_all(&self.files.cold_dependents_dir)?;
        std::fs::create_dir_all(&self.files.cold_dependents_segments_dir)?;

        // Determinism rule (Phase 7): snapshot bytes must be a pure function of (event stream,
        // cursor) and must not include wall-clock time.
        let created_at_unix_ns = 0u64;
        let (cursor_segment_seq, cursor_offset) = cursor_after.as_ref().map_or((0, 0), |c| (c.segment_seq, c.offset));

        // Snapshot 1: artifact_living_state (hot rows).
        let living_rows = encode_living_rows_v1(&self.state.living);
        let living_snapshot = CcxsnapSnapshot {
            header: CcxsnapSnapshotHeaderV1 {
                projection_id: CcxsnapProjectionId::ArtifactLivingState,
                schema_version: 1,
                created_at_unix_ns,
                shard_id: self.shard_id,
                epoch: self.epoch,
                cursor_segment_seq,
                cursor_offset,
                block_count: 1,
                codec: CCXSNAP_CODEC_NONE,
            },
            blocks: vec![(CCXSNAP_BLOCK_ROWS_V1, living_rows)],
        };
        let living_bytes = living_snapshot.encode()?;
        let living_hash = CcxsnapSnapshot::snapshot_blake3_hex(&living_bytes);
        write_atomic(&self.files.living_snapshot_path, &living_bytes)?;

        // Snapshot 2: artifact_relations (hot pointers -> cold adjacency blocks).
        self.update_relations_cold_blocks(storage, touched_relations)?;
        let relations_hot = encode_hot_ptrs_v1(&self.relations_hot_ptrs);
        let relations_seg_dir = encode_cold_segment_dir_v1(&build_reachable_segment_dir(
            &self.relations_hot_ptrs,
            &self.relations_block_locs,
            &self.relations_cold_segments,
        )?);
        let relations_snapshot = CcxsnapSnapshot {
            header: CcxsnapSnapshotHeaderV1 {
                projection_id: CcxsnapProjectionId::ArtifactRelations,
                schema_version: 3,
                created_at_unix_ns,
                shard_id: self.shard_id,
                epoch: self.epoch,
                cursor_segment_seq,
                cursor_offset,
                block_count: 2,
                codec: CCXSNAP_CODEC_NONE,
            },
            blocks: vec![
                (CCXSNAP_BLOCK_HOT_PTRS_V1, relations_hot),
                (CCXSNAP_BLOCK_COLD_SEGMENT_DIR_V1, relations_seg_dir),
            ],
        };
        let relations_bytes = relations_snapshot.encode()?;
        let relations_hash = CcxsnapSnapshot::snapshot_blake3_hex(&relations_bytes);
        write_atomic(&self.files.relations_snapshot_path, &relations_bytes)?;

        // Snapshot 3: pressure_events (hot rows).
        let pressure_rows = encode_pressure_rows_v1(&self.state.pressure);
        let pressure_snapshot = CcxsnapSnapshot {
            header: CcxsnapSnapshotHeaderV1 {
                projection_id: CcxsnapProjectionId::PressureEvents,
                schema_version: 1,
                created_at_unix_ns,
                shard_id: self.shard_id,
                epoch: self.epoch,
                cursor_segment_seq,
                cursor_offset,
                block_count: 1,
                codec: CCXSNAP_CODEC_NONE,
            },
            blocks: vec![(CCXSNAP_BLOCK_EVENTS_V1, pressure_rows)],
        };
        let pressure_bytes = pressure_snapshot.encode()?;
        let pressure_hash = CcxsnapSnapshot::snapshot_blake3_hex(&pressure_bytes);
        write_atomic(&self.files.pressure_snapshot_path, &pressure_bytes)?;

        // Snapshot 4: artifact_dependents (hot pointers -> cold adjacency blocks).
        self.update_dependents_cold_blocks(storage, touched_dependents)?;
        let dependents_hot = encode_hot_ptrs_v1(&self.dependents_hot_ptrs);
        let dependents_seg_dir = encode_cold_segment_dir_v1(&build_reachable_segment_dir(
            &self.dependents_hot_ptrs,
            &self.dependents_block_locs,
            &self.dependents_cold_segments,
        )?);
        let dependents_snapshot = CcxsnapSnapshot {
            header: CcxsnapSnapshotHeaderV1 {
                projection_id: CcxsnapProjectionId::ArtifactDependents,
                schema_version: 3,
                created_at_unix_ns,
                shard_id: self.shard_id,
                epoch: self.epoch,
                cursor_segment_seq,
                cursor_offset,
                block_count: 2,
                codec: CCXSNAP_CODEC_NONE,
            },
            blocks: vec![
                (CCXSNAP_BLOCK_HOT_PTRS_V1, dependents_hot),
                (CCXSNAP_BLOCK_COLD_SEGMENT_DIR_V1, dependents_seg_dir),
            ],
        };
        let dependents_bytes = dependents_snapshot.encode()?;
        let dependents_hash = CcxsnapSnapshot::snapshot_blake3_hex(&dependents_bytes);
        write_atomic(&self.files.dependents_snapshot_path, &dependents_bytes)?;

        // Finally: projections.meta.json (source of truth).
        self.meta.commit_id = self.meta.commit_id.saturating_add(1);
        self.meta.created_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        self.meta.artifact_living_state.schema_version = 1;
        self.meta.artifact_relations.schema_version = 3;
        self.meta.pressure_events.schema_version = 1;
        self.meta.artifact_dependents.schema_version = 3;

        self.meta.artifact_living_state.cursor.clone_from(&cursor_after);
        self.meta.artifact_relations.cursor.clone_from(&cursor_after);
        self.meta.pressure_events.cursor.clone_from(&cursor_after);
        self.meta.artifact_dependents.cursor.clone_from(&cursor_after);

        self.meta.artifact_living_state.snapshot_blake3 = Some(living_hash);
        self.meta.artifact_relations.snapshot_blake3 = Some(relations_hash);
        self.meta.pressure_events.snapshot_blake3 = Some(pressure_hash);
        self.meta.artifact_dependents.snapshot_blake3 = Some(dependents_hash);

        self.meta.artifact_living_state.row_count = self.state.living.len() as u64;
        self.meta.artifact_relations.row_count = self.state.relations.len() as u64;
        self.meta.pressure_events.row_count = self.state.pressure.len() as u64;
        self.meta.artifact_dependents.row_count = self.state.dependents.len() as u64;

        record_current_projection_modules_v1(&mut self.meta);

        store_projections_meta_v1(&self.files.meta_path, &self.meta)?;
        Ok(())
    }

    fn update_relations_cold_blocks(
        &mut self,
        _storage: &ShardStorage,
        touched: Option<&BTreeSet<(u64, u32)>>,
    ) -> Result<()> {
        let mut blocks_to_write: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();

        // Upgrade path:
        // - schema v1: flat edge list.
        // - schema v2: hot ptrs -> loose .ccxblk files.
        // - schema v3: hot ptrs -> cold segments (.ccxcseg) + segment dir block.
        let full = self.meta.artifact_relations.schema_version < 3 || touched.is_none();
        if full {
            // Ensure schema upgrades don't accidentally keep stale locs/segments.
            self.relations_cold_segments.clear();
            self.relations_block_locs.clear();
        }

        let mut keys: BTreeSet<(u64, u32)> = BTreeSet::new();
        if full {
            for (tenant_hash, src, _dst, _rt) in self.state.relations.keys() {
                keys.insert((*tenant_hash, *src));
            }
            // Ensure we also process removals for keys that existed previously.
            keys.extend(self.relations_hot_ptrs.keys().copied());
        } else if let Some(t) = touched {
            keys.extend(t.iter().copied());
        }

        for (tenant_hash, src) in keys {
            let bytes = encode_relations_edges_for_src_v1(&self.state.relations, tenant_hash, src);
            if bytes.is_empty() {
                self.relations_hot_ptrs.remove(&(tenant_hash, src));
                continue;
            }

            let h = blake3::hash(&bytes);
            let entry = HotPtrEntryV1 {
                edge_count: (bytes.len() / RELATION_EDGE_STRIDE_V1) as u32,
                block_len: bytes.len() as u32,
                codec: 0,
                blake3: *h.as_bytes(),
            };

            if !self.relations_block_locs.contains_key(&entry.blake3) {
                blocks_to_write.insert(entry.blake3, bytes);
            }
            self.relations_hot_ptrs.insert((tenant_hash, src), entry);
        }

        write_cold_segments_for_blocks(
            &self.files.cold_relations_segments_dir,
            &mut self.relations_cold_segments,
            &mut self.relations_block_locs,
            blocks_to_write,
        )?;
        Ok(())
    }

    fn update_dependents_cold_blocks(
        &mut self,
        _storage: &ShardStorage,
        touched: Option<&BTreeSet<(u64, u32)>>,
    ) -> Result<()> {
        let mut blocks_to_write: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();

        let full = self.meta.artifact_dependents.schema_version < 3 || touched.is_none();
        if full {
            self.dependents_cold_segments.clear();
            self.dependents_block_locs.clear();
        }

        let mut keys: BTreeSet<(u64, u32)> = BTreeSet::new();
        if full {
            for (tenant_hash, artifact_id, _dt, _did) in self.state.dependents.keys() {
                keys.insert((*tenant_hash, *artifact_id));
            }
            keys.extend(self.dependents_hot_ptrs.keys().copied());
        } else if let Some(t) = touched {
            keys.extend(t.iter().copied());
        }

        for (tenant_hash, artifact_id) in keys {
            let bytes = encode_dependents_edges_for_artifact_v1(&self.state.dependents, tenant_hash, artifact_id);
            if bytes.is_empty() {
                self.dependents_hot_ptrs.remove(&(tenant_hash, artifact_id));
                continue;
            }

            let h = blake3::hash(&bytes);
            let entry = HotPtrEntryV1 {
                edge_count: (bytes.len() / DEPENDENT_EDGE_STRIDE_V1) as u32,
                block_len: bytes.len() as u32,
                codec: 0,
                blake3: *h.as_bytes(),
            };

            if !self.dependents_block_locs.contains_key(&entry.blake3) {
                blocks_to_write.insert(entry.blake3, bytes);
            }
            self.dependents_hot_ptrs.insert((tenant_hash, artifact_id), entry);
        }

        write_cold_segments_for_blocks(
            &self.files.cold_dependents_segments_dir,
            &mut self.dependents_cold_segments,
            &mut self.dependents_block_locs,
            blocks_to_write,
        )?;
        Ok(())
    }

    pub fn gc_orphan_cold_segments_v1(&mut self, opts: ColdSegmentGcOptionsV1) -> Result<ColdSegmentGcReportV1> {
        let rel_reachable = reachable_cold_segments_from_snapshot_v1(
            &self.files.relations_snapshot_path,
            self.meta.artifact_relations.schema_version,
            self.meta.artifact_relations.snapshot_blake3.as_deref(),
        )?;
        let dep_reachable = reachable_cold_segments_from_snapshot_v1(
            &self.files.dependents_snapshot_path,
            self.meta.artifact_dependents.schema_version,
            self.meta.artifact_dependents.snapshot_blake3.as_deref(),
        )?;

        let (relations_report, rel_deleted) = gc_cold_segments_dir_v1(
            "relations",
            self.meta.artifact_relations.schema_version,
            &self.files.cold_relations_segments_dir,
            rel_reachable.as_ref(),
            &opts,
        )?;
        let (dependents_report, dep_deleted) = gc_cold_segments_dir_v1(
            "dependents",
            self.meta.artifact_dependents.schema_version,
            &self.files.cold_dependents_segments_dir,
            dep_reachable.as_ref(),
            &opts,
        )?;

        if !rel_deleted.is_empty() {
            self.relations_cold_segments.retain(|seg, _| !rel_deleted.contains(seg));
            self.relations_block_locs
                .retain(|_block, loc| !rel_deleted.contains(&loc.segment_blake3));
        }
        if !dep_deleted.is_empty() {
            self.dependents_cold_segments
                .retain(|seg, _| !dep_deleted.contains(seg));
            self.dependents_block_locs
                .retain(|_block, loc| !dep_deleted.contains(&loc.segment_blake3));
        }

        // Safety: ensure current hot pointers still resolve to block locations after GC.
        for p in self.relations_hot_ptrs.values() {
            if self.meta.artifact_relations.schema_version >= 3 && !self.relations_block_locs.contains_key(&p.blake3) {
                return Err(ProjectionError::InvalidEvent {
                    msg: "relations hot ptr references missing cold block loc after GC".to_string(),
                });
            }
        }
        for p in self.dependents_hot_ptrs.values() {
            if self.meta.artifact_dependents.schema_version >= 3 && !self.dependents_block_locs.contains_key(&p.blake3)
            {
                return Err(ProjectionError::InvalidEvent {
                    msg: "dependents hot ptr references missing cold block loc after GC".to_string(),
                });
            }
        }

        Ok(ColdSegmentGcReportV1 {
            shard_id: self.shard_id,
            epoch: self.epoch,
            dry_run: opts.dry_run,
            min_age_seconds: opts.min_age_seconds,
            max_delete: opts.max_delete,
            relations: relations_report,
            dependents: dependents_report,
        })
    }
}

fn cold_block_path_v1(base_dir: &Path, blake3_bytes: &[u8; 32]) -> PathBuf {
    let hex = blake3::Hash::from(*blake3_bytes).to_hex().to_string();
    let prefix = &hex[0..2];
    base_dir.join(prefix).join(format!("{hex}.ccxblk"))
}

// Fallible only on unix; off-unix the body compiles away and the Result looks
// redundant to clippy. The signature is shared, so suppress rather than change it.
#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
fn fsync_dir(path: &Path) -> std::io::Result<()> {
    // Directory fsync is a no-op off unix; bind the parameter so the
    // workspace-wide `unused_variables = "deny"` does not fail the build there.
    #[cfg(not(unix))]
    let _ = path;
    #[cfg(unix)]
    {
        let dir = std::fs::File::open(path)?;
        dir.sync_all()?;
    }
    Ok(())
}

const COLD_SEGMENT_MAX_BYTES_V1: usize = 64 * 1024 * 1024;

fn ensure_cold_segment_written(segments_dir: &Path, segment_blake3: &[u8; 32], bytes: &[u8]) -> Result<PathBuf> {
    let final_path = cold_segment_path_v1(segments_dir, segment_blake3);
    if final_path.exists() {
        return Ok(final_path);
    }
    let parent = final_path.parent().ok_or_else(|| ProjectionError::InvalidEvent {
        msg: "cold segment path missing parent".to_string(),
    })?;
    std::fs::create_dir_all(parent)?;

    // Write to a temp path in the same directory, then rename into place. This avoids producing
    // partially-written files at the content-addressed final name on crash.
    let tmp_path = final_path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp_path)?;

    f.write_all(bytes)?;
    f.flush()?;
    f.sync_all()?;
    drop(f);

    match std::fs::rename(&tmp_path, &final_path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Race: another writer published the same content-addressed block first.
            let _ = std::fs::remove_file(&tmp_path);
        }
        Err(e) => return Err(e.into()),
    }
    let _ = fsync_dir(parent);
    Ok(final_path)
}

fn write_cold_segments_for_blocks(
    segments_dir: &Path,
    segs_out: &mut BTreeMap<[u8; 32], u64>,
    locs_out: &mut BTreeMap<[u8; 32], ColdBlockLocV1>,
    blocks: BTreeMap<[u8; 32], Vec<u8>>,
) -> Result<()> {
    if blocks.is_empty() {
        return Ok(());
    }

    let mut cur: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    let mut cur_bytes = 0usize;

    let mut flush = |cur: &mut BTreeMap<[u8; 32], Vec<u8>>, cur_bytes: &mut usize| -> Result<()> {
        if cur.is_empty() {
            return Ok(());
        }
        let (seg_bytes, seg_blake3, index_entries) = build_cold_segment_v1(cur);
        let _path = ensure_cold_segment_written(segments_dir, &seg_blake3, &seg_bytes)?;

        segs_out.insert(seg_blake3, seg_bytes.len() as u64);
        for ColdSegmentIndexEntryV1 {
            block_blake3,
            offset,
            len,
            codec,
        } in index_entries
        {
            if codec != 0 {
                return Err(ProjectionError::InvalidEvent {
                    msg: format!("unsupported cold segment block codec {}", codec),
                });
            }
            locs_out.insert(
                block_blake3,
                ColdBlockLocV1 {
                    segment_blake3: seg_blake3,
                    offset,
                    len,
                    codec,
                },
            );
        }

        cur.clear();
        *cur_bytes = 0;
        Ok(())
    };

    for (h, bytes) in blocks {
        let next = cur_bytes.saturating_add(bytes.len());
        if !cur.is_empty() && next > COLD_SEGMENT_MAX_BYTES_V1 {
            flush(&mut cur, &mut cur_bytes)?;
        }
        cur_bytes = cur_bytes.saturating_add(bytes.len());
        cur.insert(h, bytes);
    }
    flush(&mut cur, &mut cur_bytes)?;
    Ok(())
}

fn load_cold_segment_indexes(segments_dir: &Path, dir: &[ColdSegmentDirEntryV1]) -> Result<ColdSegmentMapsV1> {
    let mut segs: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    let mut locs: BTreeMap<[u8; 32], ColdBlockLocV1> = BTreeMap::new();

    for e in dir {
        if segs.insert(e.segment_blake3, e.file_len).is_some() {
            return Err(ProjectionError::InvalidEvent {
                msg: "cold segment dir has duplicate segment id".to_string(),
            });
        }
        let path = cold_segment_path_v1(segments_dir, &e.segment_blake3);
        let (_hdr, idx) = read_and_verify_cold_segment_index_v1(&path, &e.segment_blake3, e.file_len)?;
        for it in idx {
            if it.codec != 0 {
                return Err(ProjectionError::InvalidEvent {
                    msg: format!("unsupported cold segment block codec {}", it.codec),
                });
            }
            if locs.contains_key(&it.block_blake3) {
                return Err(ProjectionError::InvalidEvent {
                    msg: "cold segment index has duplicate block blake3".to_string(),
                });
            }
            locs.insert(
                it.block_blake3,
                ColdBlockLocV1 {
                    segment_blake3: e.segment_blake3,
                    offset: it.offset,
                    len: it.len,
                    codec: it.codec,
                },
            );
        }
    }

    Ok((segs, locs))
}

fn build_reachable_segment_dir(
    hot_ptrs: &BTreeMap<(u64, u32), HotPtrEntryV1>,
    block_locs: &BTreeMap<[u8; 32], ColdBlockLocV1>,
    cold_segments: &BTreeMap<[u8; 32], u64>,
) -> Result<BTreeMap<[u8; 32], u64>> {
    let mut out: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    for p in hot_ptrs.values() {
        let loc = block_locs.get(&p.blake3).ok_or_else(|| ProjectionError::InvalidEvent {
            msg: "hot ptr references missing cold block location".to_string(),
        })?;
        let file_len =
            cold_segments
                .get(&loc.segment_blake3)
                .copied()
                .ok_or_else(|| ProjectionError::InvalidEvent {
                    msg: "cold block location references missing cold segment".to_string(),
                })?;
        out.insert(loc.segment_blake3, file_len);
    }
    Ok(out)
}

fn load_relations_from_cold_blocks(
    files: &ProjectionFilesV1,
    ptrs: &BTreeMap<(u64, u32), HotPtrEntryV1>,
) -> Result<BTreeMap<(u64, u32, u32, u8), crate::RelationEdgeV1>> {
    let mut out: BTreeMap<(u64, u32, u32, u8), crate::RelationEdgeV1> = BTreeMap::new();
    for ((tenant_hash, src), p) in ptrs {
        let path = cold_block_path_v1(&files.cold_relations_dir, &p.blake3);
        let bytes = std::fs::read(&path)?;
        if bytes.len() != p.block_len as usize {
            return Err(ProjectionError::InvalidEvent {
                msg: format!(
                    "cold relations block length mismatch: expected {} got {}",
                    p.block_len,
                    bytes.len()
                ),
            });
        }
        let actual = blake3::hash(&bytes);
        if actual.as_bytes() != &p.blake3 {
            return Err(ProjectionError::InvalidEvent {
                msg: format!(
                    "cold relations block hash mismatch at {}: expected {} got {}",
                    path.display(),
                    blake3::Hash::from(p.blake3).to_hex(),
                    actual.to_hex()
                ),
            });
        }
        let decoded = decode_relations_edges_v1(&bytes)?;
        for (k, v) in decoded {
            if k.0 != *tenant_hash || k.1 != *src {
                return Err(ProjectionError::InvalidEvent {
                    msg: "cold relations block contains wrong tenant_hash/src keys".to_string(),
                });
            }
            out.insert(k, v);
        }
    }
    Ok(out)
}

fn load_dependents_from_cold_blocks(
    files: &ProjectionFilesV1,
    ptrs: &BTreeMap<(u64, u32), HotPtrEntryV1>,
) -> Result<BTreeMap<(u64, u32, u8, uuid::Uuid), crate::DependentEdgeV1>> {
    let mut out: BTreeMap<(u64, u32, u8, uuid::Uuid), crate::DependentEdgeV1> = BTreeMap::new();
    for ((tenant_hash, artifact_id), p) in ptrs {
        let path = cold_block_path_v1(&files.cold_dependents_dir, &p.blake3);
        let bytes = std::fs::read(&path)?;
        if bytes.len() != p.block_len as usize {
            return Err(ProjectionError::InvalidEvent {
                msg: format!(
                    "cold dependents block length mismatch: expected {} got {}",
                    p.block_len,
                    bytes.len()
                ),
            });
        }
        let actual = blake3::hash(&bytes);
        if actual.as_bytes() != &p.blake3 {
            return Err(ProjectionError::InvalidEvent {
                msg: format!(
                    "cold dependents block hash mismatch at {}: expected {} got {}",
                    path.display(),
                    blake3::Hash::from(p.blake3).to_hex(),
                    actual.to_hex()
                ),
            });
        }
        let decoded = decode_dependents_edges_v1(&bytes)?;
        for (k, v) in decoded {
            if k.0 != *tenant_hash || k.1 != *artifact_id {
                return Err(ProjectionError::InvalidEvent {
                    msg: "cold dependents block contains wrong tenant_hash/artifact_id keys".to_string(),
                });
            }
            out.insert(k, v);
        }
    }
    Ok(out)
}

fn load_relations_from_cold_segments(
    files: &ProjectionFilesV1,
    ptrs: &BTreeMap<(u64, u32), HotPtrEntryV1>,
    locs: &BTreeMap<[u8; 32], ColdBlockLocV1>,
) -> Result<BTreeMap<(u64, u32, u32, u8), crate::RelationEdgeV1>> {
    let mut out: BTreeMap<(u64, u32, u32, u8), crate::RelationEdgeV1> = BTreeMap::new();
    for ((tenant_hash, src), p) in ptrs {
        let loc = locs.get(&p.blake3).ok_or_else(|| ProjectionError::InvalidEvent {
            msg: "hot ptr references missing cold block loc".to_string(),
        })?;
        if loc.len != p.block_len {
            return Err(ProjectionError::InvalidEvent {
                msg: "hot ptr block_len != cold block loc len".to_string(),
            });
        }
        let seg_path = cold_segment_path_v1(&files.cold_relations_segments_dir, &loc.segment_blake3);
        let bytes = read_cold_segment_block_v1(&seg_path, loc.offset, loc.len)?;
        let actual = blake3::hash(&bytes);
        if actual.as_bytes() != &p.blake3 {
            return Err(ProjectionError::InvalidEvent {
                msg: format!(
                    "cold relations block hash mismatch in {}: expected {} got {}",
                    seg_path.display(),
                    blake3::Hash::from(p.blake3).to_hex(),
                    actual.to_hex()
                ),
            });
        }
        let decoded = decode_relations_edges_v1(&bytes)?;
        for (k, v) in decoded {
            if k.0 != *tenant_hash || k.1 != *src {
                return Err(ProjectionError::InvalidEvent {
                    msg: "cold relations block contains wrong tenant_hash/src keys".to_string(),
                });
            }
            out.insert(k, v);
        }
    }
    Ok(out)
}

fn load_dependents_from_cold_segments(
    files: &ProjectionFilesV1,
    ptrs: &BTreeMap<(u64, u32), HotPtrEntryV1>,
    locs: &BTreeMap<[u8; 32], ColdBlockLocV1>,
) -> Result<BTreeMap<(u64, u32, u8, uuid::Uuid), crate::DependentEdgeV1>> {
    let mut out: BTreeMap<(u64, u32, u8, uuid::Uuid), crate::DependentEdgeV1> = BTreeMap::new();
    for ((tenant_hash, artifact_id), p) in ptrs {
        let loc = locs.get(&p.blake3).ok_or_else(|| ProjectionError::InvalidEvent {
            msg: "hot ptr references missing cold block loc".to_string(),
        })?;
        if loc.len != p.block_len {
            return Err(ProjectionError::InvalidEvent {
                msg: "hot ptr block_len != cold block loc len".to_string(),
            });
        }
        let seg_path = cold_segment_path_v1(&files.cold_dependents_segments_dir, &loc.segment_blake3);
        let bytes = read_cold_segment_block_v1(&seg_path, loc.offset, loc.len)?;
        let actual = blake3::hash(&bytes);
        if actual.as_bytes() != &p.blake3 {
            return Err(ProjectionError::InvalidEvent {
                msg: format!(
                    "cold dependents block hash mismatch in {}: expected {} got {}",
                    seg_path.display(),
                    blake3::Hash::from(p.blake3).to_hex(),
                    actual.to_hex()
                ),
            });
        }
        let decoded = decode_dependents_edges_v1(&bytes)?;
        for (k, v) in decoded {
            if k.0 != *tenant_hash || k.1 != *artifact_id {
                return Err(ProjectionError::InvalidEvent {
                    msg: "cold dependents block contains wrong tenant_hash/artifact_id keys".to_string(),
                });
            }
            out.insert(k, v);
        }
    }
    Ok(out)
}

fn reachable_cold_segments_from_snapshot_v1(
    snapshot_path: &Path,
    schema_version: u32,
    expected_snapshot_blake3: Option<&str>,
) -> Result<Option<BTreeMap<[u8; 32], u64>>> {
    if schema_version < 3 {
        return Ok(None);
    }
    let Some(expected) = expected_snapshot_blake3 else {
        return Ok(None);
    };
    if !snapshot_path.exists() {
        return Err(ProjectionError::InvalidEvent {
            msg: format!(
                "snapshot missing but projections.meta.json has snapshotBlake3: {}",
                snapshot_path.display()
            ),
        });
    }

    let bytes = std::fs::read(snapshot_path)?;
    let actual = CcxsnapSnapshot::snapshot_blake3_hex(&bytes);
    if actual != expected {
        return Err(ProjectionError::InvalidEvent {
            msg: format!(
                "snapshot blake3 mismatch at {}: expected {} got {}",
                snapshot_path.display(),
                expected,
                actual
            ),
        });
    }

    let snap = CcxsnapSnapshot::decode(&bytes)?;
    let Some((_, dir_block)) = snap
        .blocks
        .iter()
        .find(|(t, _)| *t == CCXSNAP_BLOCK_COLD_SEGMENT_DIR_V1)
    else {
        return Err(ProjectionError::InvalidEvent {
            msg: format!("snapshot missing cold segment dir block at {}", snapshot_path.display()),
        });
    };
    let dir = decode_cold_segment_dir_v1(dir_block)?;
    let mut out: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    for ColdSegmentDirEntryV1 {
        segment_blake3,
        file_len,
    } in dir
    {
        out.insert(segment_blake3, file_len);
    }
    Ok(Some(out))
}

fn gc_cold_segments_dir_v1(
    projection: &str,
    schema_version: u32,
    segments_dir: &Path,
    reachable: Option<&BTreeMap<[u8; 32], u64>>,
    opts: &ColdSegmentGcOptionsV1,
) -> Result<(ColdSegmentGcProjectionReportV1, BTreeSet<[u8; 32]>)> {
    let mut segments_on_disk = 0u64;
    let mut orphan_segments = 0u64;
    let mut deleted_segments = 0u64;
    let mut deleted_bytes = 0u64;
    let mut skipped_young_segments = 0u64;
    let mut kept_orphans_due_to_limit = 0u64;
    let mut unparseable_segment_files = 0u64;
    let mut deleted: BTreeSet<[u8; 32]> = BTreeSet::new();

    // D-28: `collect_files_recursive_v1` swallows an unreadable directory, so
    // a MISSING segments dir walked nothing and reported an all-zero clean
    // sweep — identical to a directory that was walked and held no orphans.
    // The report already carries a `skipped` shape; use it.
    if !segments_dir.is_dir() {
        return Ok((
            ColdSegmentGcProjectionReportV1 {
                projection: projection.to_string(),
                schema_version,
                skipped: true,
                skip_reason: Some(format!("segments dir not present: {}", segments_dir.display())),
                reachable_segments: reachable.map_or(0, |r| r.len() as u64),
                segments_on_disk: 0,
                orphan_segments: 0,
                deleted_segments: 0,
                deleted_bytes: 0,
                skipped_young_segments: 0,
                kept_orphans_due_to_limit: 0,
                unparseable_segment_files: 0,
            },
            deleted,
        ));
    }

    let Some(reachable) = reachable else {
        // We cannot safely determine reachability. Still report what exists on disk.
        let files = collect_files_recursive_v1(segments_dir)?;
        for p in files {
            if p.extension().and_then(|s| s.to_str()) == Some("ccxcseg") {
                segments_on_disk = segments_on_disk.saturating_add(1);
            }
        }
        return Ok((
            ColdSegmentGcProjectionReportV1 {
                projection: projection.to_string(),
                schema_version,
                skipped: true,
                skip_reason: Some("no reachable segment dir (schema<3 or missing snapshot)".into()),
                reachable_segments: 0,
                segments_on_disk,
                orphan_segments: 0,
                deleted_segments: 0,
                deleted_bytes: 0,
                skipped_young_segments: 0,
                kept_orphans_due_to_limit: 0,
                unparseable_segment_files: 0,
            },
            deleted,
        ));
    };

    let cutoff = if opts.min_age_seconds == 0 {
        None
    } else {
        Some(std::time::SystemTime::now().checked_sub(std::time::Duration::from_secs(opts.min_age_seconds))).flatten()
    };

    let files = collect_files_recursive_v1(segments_dir)?;
    for p in files {
        if p.extension().and_then(|s| s.to_str()) != Some("ccxcseg") {
            continue;
        }
        segments_on_disk = segments_on_disk.saturating_add(1);

        let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else {
            unparseable_segment_files = unparseable_segment_files.saturating_add(1);
            continue;
        };
        let Ok(h) = blake3::Hash::from_hex(stem) else {
            unparseable_segment_files = unparseable_segment_files.saturating_add(1);
            continue;
        };
        let seg_id: [u8; 32] = *h.as_bytes();

        if reachable.contains_key(&seg_id) {
            continue;
        }

        orphan_segments = orphan_segments.saturating_add(1);
        if let Some(cut) = cutoff {
            let meta = std::fs::metadata(&p)?;
            if let Ok(modified) = meta.modified() {
                if modified > cut {
                    skipped_young_segments = skipped_young_segments.saturating_add(1);
                    continue;
                }
            }
        }

        if opts.max_delete != 0 && deleted_segments >= opts.max_delete {
            kept_orphans_due_to_limit = kept_orphans_due_to_limit.saturating_add(1);
            continue;
        }

        let meta = std::fs::metadata(&p)?;
        let len = meta.len();

        if !opts.dry_run {
            std::fs::remove_file(&p)?;
            let _ = remove_parent_dirs_if_empty_v1(segments_dir, &p);
        }

        deleted.insert(seg_id);
        deleted_segments = deleted_segments.saturating_add(1);
        deleted_bytes = deleted_bytes.saturating_add(len);
    }

    Ok((
        ColdSegmentGcProjectionReportV1 {
            projection: projection.to_string(),
            schema_version,
            skipped: false,
            skip_reason: None,
            reachable_segments: reachable.len() as u64,
            segments_on_disk,
            orphan_segments,
            deleted_segments,
            deleted_bytes,
            skipped_young_segments,
            kept_orphans_due_to_limit,
            unparseable_segment_files,
        },
        deleted,
    ))
}

#[allow(clippy::unnecessary_wraps)] // Result return kept for caller ergonomics with `?` chains
fn collect_files_recursive_v1(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else {
                continue;
            };
            let p = e.path();
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file() {
                out.push(p);
            }
        }
    }
    Ok(out)
}

#[allow(clippy::unnecessary_wraps)] // Result return kept for caller ergonomics
fn remove_parent_dirs_if_empty_v1(root: &Path, path: &Path) -> std::io::Result<()> {
    let mut cur = path.parent();
    while let Some(dir) = cur {
        if dir == root {
            break;
        }
        let mut it = match std::fs::read_dir(dir) {
            Ok(it) => it,
            Err(_) => break,
        };
        if it.next().is_some() {
            break;
        }
        if std::fs::remove_dir(dir).is_err() {
            break;
        }
        cur = dir.parent();
    }
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
    let mut f = OpenOptions::new().create(true).truncate(true).write(true).open(&tmp)?;
    f.write_all(bytes)?;
    f.flush()?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn infer_cursor_after_frames(frames: &ReplayFrames) -> Option<ReplayCursor> {
    let (loc, last_frame) = frames.last()?;
    Some(ReplayCursor {
        segment_seq: loc.segment_seq,
        offset: loc.offset.saturating_add(last_frame.len() as u64),
    })
}

type ProjectionInputsV1 = (u64, String, String, Vec<u8>);

fn decode_frame_projection_inputs(frame_bytes: &[u8]) -> Result<Option<ProjectionInputsV1>> {
    let decoded = decode_frame_v1(frame_bytes)?;
    if decoded.header_bytes.len() < 32 {
        return Err(ProjectionError::InvalidFrameHeader {
            msg: "header_bytes too small (<32)".to_string(),
        });
    }
    let canonical_len = decoded.header_bytes.len() - 32;
    let canonical = &decoded.header_bytes[..canonical_len];
    let hdr = decode_canonical_header_bytes_v1(canonical).map_err(|e| ProjectionError::InvalidFrameHeader {
        msg: format!("canonical header decode failed: {e}"),
    })?;
    let tenant_hash = crate::state::tenant_hash_xxhash64(&hdr.tenant_id);
    Ok(Some((
        tenant_hash,
        hdr.event_type,
        hdr.content_type,
        decoded.payload_bytes,
    )))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    // ── ProjectionFilesV1::for_shard_dir ────────────────────────────

    #[test]
    fn projection_files_for_shard_dir_layout() {
        let files = ProjectionFilesV1::for_shard_dir(Path::new("/data/shard-0001"));
        assert_eq!(files.projections_dir, PathBuf::from("/data/shard-0001/projections"));
        assert_eq!(
            files.meta_path,
            PathBuf::from("/data/shard-0001/projections/projections.meta.json")
        );
        assert_eq!(
            files.living_snapshot_path,
            PathBuf::from("/data/shard-0001/projections/artifact_living_state.snapshot.ccxsnap")
        );
        assert_eq!(
            files.relations_snapshot_path,
            PathBuf::from("/data/shard-0001/projections/artifact_relations.snapshot.ccxsnap")
        );
        assert_eq!(
            files.pressure_snapshot_path,
            PathBuf::from("/data/shard-0001/projections/pressure_events.snapshot.ccxsnap")
        );
        assert_eq!(
            files.dependents_snapshot_path,
            PathBuf::from("/data/shard-0001/projections/artifact_dependents.snapshot.ccxsnap")
        );
        assert_eq!(
            files.cold_relations_dir,
            PathBuf::from("/data/shard-0001/projections/cold/relations")
        );
        assert_eq!(
            files.cold_relations_segments_dir,
            PathBuf::from("/data/shard-0001/projections/cold/relations/segments")
        );
        assert_eq!(
            files.cold_dependents_dir,
            PathBuf::from("/data/shard-0001/projections/cold/dependents")
        );
        assert_eq!(
            files.cold_dependents_segments_dir,
            PathBuf::from("/data/shard-0001/projections/cold/dependents/segments")
        );
    }

    #[test]
    fn projection_files_clone_and_debug() {
        let files = ProjectionFilesV1::for_shard_dir(Path::new("/x"));
        let cloned = files.clone();
        assert_eq!(cloned.projections_dir, files.projections_dir);
        let dbg = format!("{:?}", files);
        assert!(dbg.contains("projections"));
    }

    // ── cold_block_path_v1 ──────────────────────────────────────────

    #[test]
    fn cold_block_path_v1_structure() {
        let hash_bytes = [0xAA; 32];
        let path = cold_block_path_v1(Path::new("/cold/segments"), &hash_bytes);
        let path_str = path.to_string_lossy();
        // Should be /cold/segments/<2-char-prefix>/<full-hex>.ccxblk
        assert!(path_str.contains(".ccxblk"));
        assert!(path_str.starts_with("/cold/segments/"));
    }

    #[test]
    fn cold_block_path_v1_deterministic() {
        let hash = [0x42; 32];
        let p1 = cold_block_path_v1(Path::new("/x"), &hash);
        let p2 = cold_block_path_v1(Path::new("/x"), &hash);
        assert_eq!(p1, p2);
    }

    #[test]
    fn cold_block_path_v1_different_hashes_differ() {
        let h1 = [0x00; 32];
        let h2 = [0xFF; 32];
        let p1 = cold_block_path_v1(Path::new("/x"), &h1);
        let p2 = cold_block_path_v1(Path::new("/x"), &h2);
        assert_ne!(p1, p2);
    }

    // ── collect_files_recursive_v1 ──────────────────────────────────

    #[test]
    fn collect_files_recursive_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let files = collect_files_recursive_v1(tmp.path()).unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn collect_files_recursive_finds_nested() {
        let tmp = TempDir::new().unwrap();
        let sub = tmp.path().join("a").join("b");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(tmp.path().join("top.txt"), b"top").unwrap();
        std::fs::write(sub.join("nested.txt"), b"nested").unwrap();
        let files = collect_files_recursive_v1(tmp.path()).unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn collect_files_recursive_missing_root() {
        let tmp = TempDir::new().unwrap();
        let missing = tmp.path().join("nonexistent");
        let files = collect_files_recursive_v1(&missing).unwrap();
        assert!(files.is_empty());
    }

    // ── remove_parent_dirs_if_empty_v1 ──────────────────────────────

    #[test]
    fn remove_parent_dirs_if_empty_cleans_up() {
        let tmp = TempDir::new().unwrap();
        let nested = tmp.path().join("a").join("b").join("c");
        std::fs::create_dir_all(&nested).unwrap();
        let file = nested.join("file.txt");
        std::fs::write(&file, b"data").unwrap();

        // Remove file, then clean parent dirs
        std::fs::remove_file(&file).unwrap();
        remove_parent_dirs_if_empty_v1(tmp.path(), &file).unwrap();
        // "c" should be removed, "b" should be removed, "a" should be removed
        assert!(!tmp.path().join("a").exists());
    }

    #[test]
    fn remove_parent_dirs_stops_at_non_empty() {
        let tmp = TempDir::new().unwrap();
        let nested = tmp.path().join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(tmp.path().join("a").join("keep.txt"), b"keep").unwrap();
        let file = nested.join("gone.txt");
        std::fs::write(&file, b"data").unwrap();

        std::fs::remove_file(&file).unwrap();
        remove_parent_dirs_if_empty_v1(tmp.path(), &file).unwrap();
        // "b" removed, but "a" has keep.txt so it stays
        assert!(!nested.exists());
        assert!(tmp.path().join("a").exists());
    }

    #[test]
    fn remove_parent_dirs_stops_at_root() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("file.txt");
        std::fs::write(&file, b"data").unwrap();
        std::fs::remove_file(&file).unwrap();
        remove_parent_dirs_if_empty_v1(tmp.path(), &file).unwrap();
        // Root dir should still exist
        assert!(tmp.path().exists());
    }

    // ── write_atomic ────────────────────────────────────────────────

    #[test]
    fn write_atomic_creates_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.bin");
        write_atomic(&path, b"hello world").unwrap();
        let content = std::fs::read(&path).unwrap();
        assert_eq!(content, b"hello world");
    }

    #[test]
    fn write_atomic_creates_parent_dirs() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("a").join("b").join("test.bin");
        write_atomic(&path, b"nested").unwrap();
        assert!(path.exists());
    }

    #[test]
    fn write_atomic_overwrites_existing() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.bin");
        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second").unwrap();
        let content = std::fs::read(&path).unwrap();
        assert_eq!(content, b"second");
    }

    // ── infer_cursor_after_frames ──────────────────────────────────

    #[test]
    fn infer_cursor_empty_frames() {
        let frames: ReplayFrames = Vec::new();
        assert!(infer_cursor_after_frames(&frames).is_none());
    }

    // ── ProjectionsTickResultV1 serialization ───────────────────────

    #[test]
    fn projections_tick_result_serializes() {
        let result = ProjectionsTickResultV1 {
            frames_processed: 100,
            cursor_before: None,
            cursor_after: Some(ProjectionCursorV1 {
                shard_id: 1,
                epoch: 1,
                segment_seq: 42,
                offset: 1024,
            }),
            commit_id: 7,
            state_counts: ProjectionCountsV1 {
                living_rows: 50,
                relations_edges: 30,
                dependents_edges: 20,
                pressure_rows: 10,
            },
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["frames_processed"], 100);
        assert_eq!(json["commit_id"], 7);
        assert_eq!(json["state_counts"]["living_rows"], 50);
    }

    // ── ColdSegmentGcOptionsV1 ──────────────────────────────────────

    #[test]
    fn cold_segment_gc_options_clone_and_debug() {
        let opts = ColdSegmentGcOptionsV1 {
            dry_run: true,
            min_age_seconds: 3600,
            max_delete: 100,
        };
        let cloned = opts.clone();
        assert!(cloned.dry_run);
        assert_eq!(cloned.min_age_seconds, 3600);
        assert_eq!(cloned.max_delete, 100);
        let dbg = format!("{:?}", opts);
        assert!(dbg.contains("dry_run"));
    }

    // ── ColdSegmentGcReportV1 serialization ─────────────────────────

    #[test]
    fn cold_segment_gc_report_serializes() {
        let report = ColdSegmentGcReportV1 {
            shard_id: 1,
            epoch: 3,
            dry_run: false,
            min_age_seconds: 7200,
            max_delete: 50,
            relations: ColdSegmentGcProjectionReportV1 {
                projection: "artifact_relations".to_string(),
                schema_version: 1,
                skipped: false,
                skip_reason: None,
                reachable_segments: 10,
                segments_on_disk: 15,
                orphan_segments: 5,
                deleted_segments: 3,
                deleted_bytes: 1024,
                skipped_young_segments: 2,
                kept_orphans_due_to_limit: 0,
                unparseable_segment_files: 0,
            },
            dependents: ColdSegmentGcProjectionReportV1 {
                projection: "artifact_dependents".to_string(),
                schema_version: 1,
                skipped: true,
                skip_reason: Some("no snapshot".to_string()),
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
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["shardId"], 1);
        assert_eq!(json["relations"]["deleted_segments"], 3);
        assert_eq!(json["dependents"]["skipped"], true);
        assert_eq!(json["dependents"]["skip_reason"], "no snapshot");
    }

    // ── ColdSegmentGcProjectionReportV1 ─────────────────────────────

    #[test]
    fn cold_gc_projection_report_skip_reason_omitted_when_none() {
        let report = ColdSegmentGcProjectionReportV1 {
            projection: "artifact_relations".to_string(),
            schema_version: 1,
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

    // ── ProjectionStoreV1 load_or_init ──────────────────────────────

    #[test]
    fn projection_store_load_or_init_creates_dirs() {
        let tmp = TempDir::new().unwrap();
        let shard_dir = tmp.path().join("shard-0001");
        std::fs::create_dir_all(&shard_dir).unwrap();
        let store = ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        assert!(store.files.projections_dir.exists());
        assert!(store.files.cold_relations_dir.exists());
        assert!(store.files.cold_dependents_dir.exists());
        assert_eq!(store.shard_id, 1);
        assert_eq!(store.epoch, 1);
    }

    #[test]
    fn projection_store_load_or_init_empty_state() {
        let tmp = TempDir::new().unwrap();
        let shard_dir = tmp.path().join("shard-0001");
        std::fs::create_dir_all(&shard_dir).unwrap();
        let store = ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        assert!(store.relations_hot_ptrs.is_empty());
        assert!(store.dependents_hot_ptrs.is_empty());
        assert!(store.relations_cold_segments.is_empty());
        assert!(store.dependents_cold_segments.is_empty());
    }

    // ── ensure_cold_segment_written ────────────────────────────────

    #[test]
    fn ensure_cold_segment_written_creates_file() {
        let tmp = TempDir::new().unwrap();
        let segs_dir = tmp.path().join("segments");
        std::fs::create_dir_all(&segs_dir).unwrap();
        let data = b"segment data";
        let hash = blake3::hash(data);
        let hash_bytes: [u8; 32] = *hash.as_bytes();
        let path = ensure_cold_segment_written(&segs_dir, &hash_bytes, data).unwrap();
        assert!(path.exists());
        assert_eq!(std::fs::read(&path).unwrap(), data);
    }

    #[test]
    fn ensure_cold_segment_written_idempotent() {
        let tmp = TempDir::new().unwrap();
        let segs_dir = tmp.path().join("segments");
        std::fs::create_dir_all(&segs_dir).unwrap();
        let data = b"segment data";
        let hash_bytes: [u8; 32] = *blake3::hash(data).as_bytes();
        let p1 = ensure_cold_segment_written(&segs_dir, &hash_bytes, data).unwrap();
        let p2 = ensure_cold_segment_written(&segs_dir, &hash_bytes, data).unwrap();
        assert_eq!(p1, p2);
    }

    // ── fsync_dir ───────────────────────────────────────────────────

    #[test]
    fn fsync_dir_on_tempdir_succeeds() {
        let tmp = TempDir::new().unwrap();
        let result = fsync_dir(tmp.path());
        assert!(result.is_ok());
    }

    #[test]
    fn fsync_dir_nonexistent_fails() {
        let result = fsync_dir(Path::new("/tmp/nonexistent-fsync-test-dir-corecrux"));
        assert!(result.is_err());
    }

    // ── infer_cursor_after_frames with data ─────────────────────────

    #[test]
    fn infer_cursor_single_frame() {
        let loc = corecrux_storage::FrameLocation {
            shard_id: 1,
            epoch: 1,
            segment_seq: 42,
            offset: 100,
        };
        let frame_data = vec![0u8; 256];
        let frames: ReplayFrames = vec![(loc, frame_data)];
        let cursor = infer_cursor_after_frames(&frames).unwrap();
        assert_eq!(cursor.segment_seq, 42);
        assert_eq!(cursor.offset, 100 + 256);
    }

    #[test]
    fn infer_cursor_multiple_frames_uses_last() {
        let loc1 = corecrux_storage::FrameLocation {
            shard_id: 1,
            epoch: 1,
            segment_seq: 10,
            offset: 0,
        };
        let loc2 = corecrux_storage::FrameLocation {
            shard_id: 1,
            epoch: 1,
            segment_seq: 10,
            offset: 500,
        };
        let frames: ReplayFrames = vec![(loc1, vec![0u8; 100]), (loc2, vec![0u8; 200])];
        let cursor = infer_cursor_after_frames(&frames).unwrap();
        assert_eq!(cursor.segment_seq, 10);
        assert_eq!(cursor.offset, 700); // 500 + 200
    }

    // ── cold_block_path_v1: prefix extraction ───────────────────────

    #[test]
    fn cold_block_path_v1_uses_two_char_prefix() {
        let hash = [0xDE; 32];
        let path = cold_block_path_v1(Path::new("/base"), &hash);
        let path_str = path.to_string_lossy();
        // blake3 of [0xDE; 32] will produce some hex; first 2 chars are prefix
        assert!(path_str.contains("/base/"));
        assert!(path_str.ends_with(".ccxblk"));
    }

    // ── ProjectionsTickResultV1: all fields ──────────────────────────

    #[test]
    fn projections_tick_result_with_cursor_before() {
        let result = ProjectionsTickResultV1 {
            frames_processed: 50,
            cursor_before: Some(ProjectionCursorV1 {
                shard_id: 0,
                epoch: 1,
                segment_seq: 10,
                offset: 0,
            }),
            cursor_after: Some(ProjectionCursorV1 {
                shard_id: 0,
                epoch: 1,
                segment_seq: 10,
                offset: 5000,
            }),
            commit_id: 3,
            state_counts: ProjectionCountsV1 {
                living_rows: 100,
                relations_edges: 50,
                dependents_edges: 25,
                pressure_rows: 5,
            },
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["frames_processed"], 50);
        assert_eq!(json["commit_id"], 3);
        assert!(json["cursor_before"].is_object());
        assert!(json["cursor_after"].is_object());
    }

    // ── ColdSegmentGcReportV1: additional serialization ─────────────

    #[test]
    fn cold_gc_report_dry_run_true() {
        let report = ColdSegmentGcReportV1 {
            shard_id: 0,
            epoch: 1,
            dry_run: true,
            min_age_seconds: 0,
            max_delete: 0,
            relations: ColdSegmentGcProjectionReportV1 {
                projection: "r".to_string(),
                schema_version: 1,
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
            },
            dependents: ColdSegmentGcProjectionReportV1 {
                projection: "d".to_string(),
                schema_version: 1,
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
            },
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["dry_run"], true);
    }

    // ── ProjectionStoreV1: idempotent load_or_init ──────────────────

    #[test]
    fn projection_store_load_or_init_idempotent() {
        let tmp = TempDir::new().unwrap();
        let shard_dir = tmp.path().join("shard-0001");
        std::fs::create_dir_all(&shard_dir).unwrap();
        let _store1 = ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        // Second load should succeed (idempotent)
        let store2 = ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        assert_eq!(store2.shard_id, 1);
    }

    /// D-6 (inverted pin): when meta records a `snapshotBlake3` and an
    /// advanced cursor but the snapshot FILE is gone, the
    /// `.filter(|_| …exists())` guard skipped the whole verification block and
    /// left `ok = true`. The store came back with the cursor intact and the
    /// state empty, so the next `tick` resumed past frames it had never
    /// applied. A *corrupt* snapshot already reset to genesis correctly; a
    /// *deleted* one must too.
    #[test]
    fn load_or_init_missing_snapshot_file_resets_to_genesis() {
        let tmp = TempDir::new().unwrap();
        let shard_dir = tmp.path().join("shard-0001");
        std::fs::create_dir_all(&shard_dir).unwrap();
        let files = ProjectionFilesV1::for_shard_dir(&shard_dir);
        std::fs::create_dir_all(&files.projections_dir).unwrap();

        let mut meta = crate::meta::ProjectionsMetaV1::empty_now();
        meta.commit_id = 12;
        meta.artifact_living_state.snapshot_blake3 = Some("d".repeat(64));
        meta.artifact_living_state.row_count = 500;
        meta.artifact_living_state.cursor = Some(ProjectionCursorV1 {
            shard_id: 1,
            epoch: 1,
            segment_seq: 7,
            offset: 4_096,
        });
        store_projections_meta_v1(&files.meta_path, &meta).unwrap();
        assert!(!files.living_snapshot_path.exists());

        let store = ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        assert!(store.state.living.is_empty(), "no rows were loaded");
        assert_eq!(store.meta.commit_id, 0, "meta is reset alongside the empty state");
        assert!(
            store.cursor_from_meta().is_none(),
            "the cursor must not survive a snapshot that could not be verified"
        );
    }

    /// Same defect, sibling artifacts: a declared-but-absent relations,
    /// dependents or pressure snapshot resets too.
    #[test]
    fn load_or_init_missing_sibling_snapshots_also_reset_to_genesis() {
        for artifact in ["relations", "dependents", "pressure"] {
            let tmp = TempDir::new().unwrap();
            let shard_dir = tmp.path().join("shard-0001");
            std::fs::create_dir_all(&shard_dir).unwrap();
            let files = ProjectionFilesV1::for_shard_dir(&shard_dir);
            std::fs::create_dir_all(&files.projections_dir).unwrap();

            let mut meta = crate::meta::ProjectionsMetaV1::empty_now();
            meta.commit_id = 9;
            meta.artifact_living_state.cursor = Some(ProjectionCursorV1 {
                shard_id: 1,
                epoch: 1,
                segment_seq: 3,
                offset: 64,
            });
            match artifact {
                "relations" => meta.artifact_relations.snapshot_blake3 = Some("a".repeat(64)),
                "dependents" => meta.artifact_dependents.snapshot_blake3 = Some("b".repeat(64)),
                _ => meta.pressure_events.snapshot_blake3 = Some("c".repeat(64)),
            }
            store_projections_meta_v1(&files.meta_path, &meta).unwrap();

            let store = ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
            assert_eq!(store.meta.commit_id, 0, "{artifact}: meta is reset");
            assert!(
                store.cursor_from_meta().is_none(),
                "{artifact}: the cursor must not survive"
            );
        }
    }

    /// Control: a meta that declares no snapshot at all is a clean cold start,
    /// not a reset. The fix must fire only on *declared but absent*.
    #[test]
    fn load_or_init_without_a_declared_snapshot_keeps_its_cursor() {
        let tmp = TempDir::new().unwrap();
        let shard_dir = tmp.path().join("shard-0001");
        std::fs::create_dir_all(&shard_dir).unwrap();
        let files = ProjectionFilesV1::for_shard_dir(&shard_dir);
        std::fs::create_dir_all(&files.projections_dir).unwrap();

        let mut meta = crate::meta::ProjectionsMetaV1::empty_now();
        meta.commit_id = 4;
        meta.artifact_living_state.cursor = Some(ProjectionCursorV1 {
            shard_id: 1,
            epoch: 1,
            segment_seq: 2,
            offset: 128,
        });
        store_projections_meta_v1(&files.meta_path, &meta).unwrap();

        let store = ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        assert_eq!(store.meta.commit_id, 4);
        assert_eq!(store.cursor_from_meta().expect("cursor survives").segment_seq, 2);
    }

    // ── write_atomic: empty data ────────────────────────────────────

    #[test]
    fn write_atomic_empty_data() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("empty.bin");
        write_atomic(&path, b"").unwrap();
        let content = std::fs::read(&path).unwrap();
        assert!(content.is_empty());
    }

    // ─��� collect_files_recursive: handles symlinks gracefully ─────────

    #[test]
    fn collect_files_recursive_single_file() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("a.txt"), b"a").unwrap();
        let files = collect_files_recursive_v1(tmp.path()).unwrap();
        assert_eq!(files.len(), 1);
    }

    // ── remove_parent_dirs_if_empty: deeply nested ──────────────────

    #[test]
    fn remove_parent_dirs_deeply_nested() {
        let tmp = TempDir::new().unwrap();
        let nested = tmp.path().join("a").join("b").join("c").join("d").join("e");
        std::fs::create_dir_all(&nested).unwrap();
        let file = nested.join("data.bin");
        std::fs::write(&file, b"data").unwrap();
        std::fs::remove_file(&file).unwrap();
        remove_parent_dirs_if_empty_v1(tmp.path(), &file).unwrap();
        assert!(!tmp.path().join("a").exists());
    }

    // ── ProjectionCountsV1 serialization ────────────────────────────

    #[test]
    fn projection_counts_serializes() {
        let counts = ProjectionCountsV1 {
            living_rows: 100,
            relations_edges: 200,
            dependents_edges: 300,
            pressure_rows: 400,
        };
        let json = serde_json::to_value(&counts).unwrap();
        assert_eq!(json["living_rows"], 100);
        assert_eq!(json["relations_edges"], 200);
        assert_eq!(json["dependents_edges"], 300);
        assert_eq!(json["pressure_rows"], 400);
    }

    // ── ProjectionCountsV1: clone + debug ────────────────────────────

    #[test]
    fn projection_counts_clone_and_debug() {
        let counts = ProjectionCountsV1 {
            living_rows: 1,
            relations_edges: 2,
            dependents_edges: 3,
            pressure_rows: 4,
        };
        let cloned = counts.clone();
        assert_eq!(cloned.living_rows, 1);
        let dbg = format!("{:?}", counts);
        assert!(dbg.contains("living_rows"));
    }

    // ── ProjectionFilesV1: different shard dirs ──────────────────────

    #[test]
    fn projection_files_different_shard_dirs() {
        let f1 = ProjectionFilesV1::for_shard_dir(Path::new("/a"));
        let f2 = ProjectionFilesV1::for_shard_dir(Path::new("/b"));
        assert_ne!(f1.projections_dir, f2.projections_dir);
        assert_ne!(f1.meta_path, f2.meta_path);
    }

    // ── ColdSegmentGcOptionsV1: all fields ───────────────────────────

    #[test]
    fn cold_segment_gc_options_fields() {
        let opts = ColdSegmentGcOptionsV1 {
            dry_run: false,
            min_age_seconds: 0,
            max_delete: 0,
        };
        assert!(!opts.dry_run);
        assert_eq!(opts.min_age_seconds, 0);
        assert_eq!(opts.max_delete, 0);
    }

    // ── ColdSegmentGcProjectionReportV1: clone + debug ───────────────

    #[test]
    fn cold_gc_projection_report_clone_debug() {
        let report = ColdSegmentGcProjectionReportV1 {
            projection: "test".to_string(),
            schema_version: 3,
            skipped: false,
            skip_reason: None,
            reachable_segments: 10,
            segments_on_disk: 15,
            orphan_segments: 5,
            deleted_segments: 0,
            deleted_bytes: 0,
            skipped_young_segments: 0,
            kept_orphans_due_to_limit: 0,
            unparseable_segment_files: 0,
        };
        let cloned = report.clone();
        assert_eq!(cloned.schema_version, 3);
        let dbg = format!("{:?}", report);
        assert!(dbg.contains("reachable_segments"));
    }

    // ── ColdSegmentGcReportV1: clone + debug ─────────────────────────

    #[test]
    fn cold_gc_report_clone_debug() {
        let proj = ColdSegmentGcProjectionReportV1 {
            projection: "x".to_string(),
            schema_version: 1,
            skipped: true,
            skip_reason: Some("test".to_string()),
            reachable_segments: 0,
            segments_on_disk: 0,
            orphan_segments: 0,
            deleted_segments: 0,
            deleted_bytes: 0,
            skipped_young_segments: 0,
            kept_orphans_due_to_limit: 0,
            unparseable_segment_files: 0,
        };
        let report = ColdSegmentGcReportV1 {
            shard_id: 1,
            epoch: 2,
            dry_run: true,
            min_age_seconds: 3600,
            max_delete: 10,
            relations: proj.clone(),
            dependents: proj,
        };
        let cloned = report.clone();
        assert_eq!(cloned.shard_id, 1);
        assert_eq!(cloned.epoch, 2);
        let dbg = format!("{:?}", report);
        assert!(dbg.contains("dry_run"));
    }

    // ── ProjectionsTickResultV1: clone + debug ───────────────────────

    #[test]
    fn projections_tick_result_clone_debug() {
        let result = ProjectionsTickResultV1 {
            frames_processed: 10,
            cursor_before: None,
            cursor_after: None,
            commit_id: 1,
            state_counts: ProjectionCountsV1 {
                living_rows: 0,
                relations_edges: 0,
                dependents_edges: 0,
                pressure_rows: 0,
            },
        };
        let cloned = result.clone();
        assert_eq!(cloned.frames_processed, 10);
        let dbg = format!("{:?}", result);
        assert!(dbg.contains("commit_id"));
    }

    // ── cold_segment_path_v1 ─────────────────────────────────────────

    #[test]
    fn cold_segment_path_v1_deterministic() {
        let hash = [0x42u8; 32];
        let p1 = cold_segment_path_v1(Path::new("/base"), &hash);
        let p2 = cold_segment_path_v1(Path::new("/base"), &hash);
        assert_eq!(p1, p2);
        assert!(p1.to_string_lossy().ends_with(".ccxcseg"));
        assert!(p1.to_string_lossy().starts_with("/base/"));
    }

    #[test]
    fn cold_segment_path_v1_different_hashes_differ() {
        let h1 = [0x00u8; 32];
        let h2 = [0xFFu8; 32];
        let p1 = cold_segment_path_v1(Path::new("/x"), &h1);
        let p2 = cold_segment_path_v1(Path::new("/x"), &h2);
        assert_ne!(p1, p2);
    }

    // ── write_atomic: large data ─────────────────────────────────────

    #[test]
    fn write_atomic_large_data() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("large.bin");
        let data = vec![0xABu8; 100_000];
        write_atomic(&path, &data).unwrap();
        let read = std::fs::read(&path).unwrap();
        assert_eq!(read.len(), 100_000);
    }

    // ── ProjectionStoreV1: different shard ids ───────────────────────

    #[test]
    fn projection_store_different_shard_ids() {
        let tmp = TempDir::new().unwrap();
        let s1 = tmp.path().join("shard-0001");
        let s2 = tmp.path().join("shard-0002");
        std::fs::create_dir_all(&s1).unwrap();
        std::fs::create_dir_all(&s2).unwrap();
        let store1 = ProjectionStoreV1::load_or_init(&s1, 1, 1).unwrap();
        let store2 = ProjectionStoreV1::load_or_init(&s2, 2, 1).unwrap();
        assert_eq!(store1.shard_id, 1);
        assert_eq!(store2.shard_id, 2);
    }

    // ── ProjectionStoreV1: cursor_from_meta is None initially ────────

    #[test]
    fn projection_store_cursor_from_meta_none() {
        let tmp = TempDir::new().unwrap();
        let shard_dir = tmp.path().join("shard-0001");
        std::fs::create_dir_all(&shard_dir).unwrap();
        let store = ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        assert!(store.cursor_from_meta().is_none());
    }

    // ── ProjectionStoreV1: cursor_v1_from_replay ─────────────────────

    #[test]
    fn projection_store_cursor_v1_from_replay() {
        let tmp = TempDir::new().unwrap();
        let shard_dir = tmp.path().join("shard-0001");
        std::fs::create_dir_all(&shard_dir).unwrap();
        let store = ProjectionStoreV1::load_or_init(&shard_dir, 1, 5).unwrap();
        let cursor = store.cursor_v1_from_replay(corecrux_storage::ReplayCursor {
            segment_seq: 42,
            offset: 100,
        });
        assert_eq!(cursor.shard_id, 1);
        assert_eq!(cursor.epoch, 5);
        assert_eq!(cursor.segment_seq, 42);
        assert_eq!(cursor.offset, 100);
    }

    // ══════════════════════════════════════════════════════════════════
    // Failure-detection coverage for the cold-block / cold-segment plane
    // and the GC reporter. These paths decide whether a corrupted or
    // partially-GC'd projection is *noticed*; the happy paths already
    // live in `runner_tests.rs`.
    // ══════════════════════════════════════════════════════════════════

    fn rel_edge(at: i64) -> crate::RelationEdgeV1 {
        crate::RelationEdgeV1 {
            confidence_q16: 32_768,
            evidence_ref_hash16: [0x5A; 16],
            created_at_micros: at,
            updated_at_micros: at,
        }
    }

    fn dep_edge(at: i64) -> crate::DependentEdgeV1 {
        crate::DependentEdgeV1 {
            last_seen_at_micros: at,
            usage_weight_q16: 4_096,
        }
    }

    /// Encode one relations block for `(tenant, src)` and return
    /// `(bytes, hot_ptr)` with a correct content-addressed hash.
    fn relations_block(tenant: u64, src: u32) -> (Vec<u8>, HotPtrEntryV1) {
        let mut edges: BTreeMap<(u64, u32, u32, u8), crate::RelationEdgeV1> = BTreeMap::new();
        edges.insert((tenant, src, src + 1, 0u8), rel_edge(10));
        edges.insert((tenant, src, src + 2, 1u8), rel_edge(20));
        let bytes = encode_relations_edges_for_src_v1(&edges, tenant, src);
        let ptr = HotPtrEntryV1 {
            edge_count: (bytes.len() / RELATION_EDGE_STRIDE_V1) as u32,
            block_len: bytes.len() as u32,
            codec: 0,
            blake3: *blake3::hash(&bytes).as_bytes(),
        };
        (bytes, ptr)
    }

    /// Encode one dependents block for `(tenant, artifact)` and return
    /// `(bytes, hot_ptr)` with a correct content-addressed hash.
    fn dependents_block(tenant: u64, artifact: u32) -> (Vec<u8>, HotPtrEntryV1) {
        let mut edges: BTreeMap<(u64, u32, u8, uuid::Uuid), crate::DependentEdgeV1> = BTreeMap::new();
        edges.insert((tenant, artifact, 0u8, uuid::Uuid::from_bytes([1u8; 16])), dep_edge(11));
        let bytes = encode_dependents_edges_for_artifact_v1(&edges, tenant, artifact);
        let ptr = HotPtrEntryV1 {
            edge_count: (bytes.len() / DEPENDENT_EDGE_STRIDE_V1) as u32,
            block_len: bytes.len() as u32,
            codec: 0,
            blake3: *blake3::hash(&bytes).as_bytes(),
        };
        (bytes, ptr)
    }

    fn write_cold_block(dir: &Path, blake3_bytes: &[u8; 32], bytes: &[u8]) {
        let path = cold_block_path_v1(dir, blake3_bytes);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
    }

    fn files_in(tmp: &TempDir) -> ProjectionFilesV1 {
        let files = ProjectionFilesV1::for_shard_dir(tmp.path());
        std::fs::create_dir_all(&files.cold_relations_segments_dir).unwrap();
        std::fs::create_dir_all(&files.cold_dependents_segments_dir).unwrap();
        files
    }

    // ── build_reachable_segment_dir ─────────────────────────────────

    #[test]
    fn build_reachable_segment_dir_empty_is_empty() {
        let out = build_reachable_segment_dir(&BTreeMap::new(), &BTreeMap::new(), &BTreeMap::new()).unwrap();
        assert!(out.is_empty());
    }

    /// A hot pointer with no matching cold-block location means the snapshot
    /// we are about to write would dangle. Catch it at build time, not at the
    /// next load.
    #[test]
    fn build_reachable_segment_dir_missing_block_loc_errors() {
        let (_bytes, ptr) = relations_block(7, 1);
        let mut ptrs = BTreeMap::new();
        ptrs.insert((7u64, 1u32), ptr.clone());
        let err = build_reachable_segment_dir(&ptrs, &BTreeMap::new(), &BTreeMap::new()).unwrap_err();
        assert!(
            format!("{err}").contains("missing cold block location"),
            "unexpected error: {err}"
        );
    }

    /// A block location that names a segment absent from the segment table is
    /// equally fatal: the dir block would reference a file we never wrote.
    #[test]
    fn build_reachable_segment_dir_missing_segment_errors() {
        let (_bytes, ptr) = relations_block(7, 1);
        let mut ptrs = BTreeMap::new();
        ptrs.insert((7u64, 1u32), ptr.clone());
        let mut locs = BTreeMap::new();
        locs.insert(
            ptr.blake3,
            ColdBlockLocV1 {
                segment_blake3: [0xAB; 32],
                offset: 128,
                len: ptr.block_len,
                codec: 0,
            },
        );
        let err = build_reachable_segment_dir(&ptrs, &locs, &BTreeMap::new()).unwrap_err();
        assert!(
            format!("{err}").contains("missing cold segment"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn build_reachable_segment_dir_dedups_shared_segment() {
        let (_b1, p1) = relations_block(7, 1);
        let (_b2, p2) = relations_block(7, 2);
        let seg = [0xCD; 32];
        let mut ptrs = BTreeMap::new();
        ptrs.insert((7u64, 1u32), p1.clone());
        ptrs.insert((7u64, 2u32), p2.clone());
        let mut locs = BTreeMap::new();
        for p in [p1, p2] {
            locs.insert(
                p.blake3,
                ColdBlockLocV1 {
                    segment_blake3: seg,
                    offset: 128,
                    len: p.block_len,
                    codec: 0,
                },
            );
        }
        let mut segs = BTreeMap::new();
        segs.insert(seg, 4_242u64);
        let out = build_reachable_segment_dir(&ptrs, &locs, &segs).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out.get(&seg), Some(&4_242u64));
    }

    // ── write_cold_segments_for_blocks + load_cold_segment_indexes ──

    #[test]
    fn write_cold_segments_for_empty_block_set_writes_nothing() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("segments");
        std::fs::create_dir_all(&dir).unwrap();
        let mut segs = BTreeMap::new();
        let mut locs = BTreeMap::new();
        write_cold_segments_for_blocks(&dir, &mut segs, &mut locs, BTreeMap::new()).unwrap();
        assert!(segs.is_empty());
        assert!(locs.is_empty());
        assert!(collect_files_recursive_v1(&dir).unwrap().is_empty());
    }

    #[test]
    fn write_then_load_cold_segment_indexes_round_trips() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("segments");
        std::fs::create_dir_all(&dir).unwrap();

        let (b1, p1) = relations_block(9, 1);
        let (b2, p2) = relations_block(9, 2);
        let mut blocks = BTreeMap::new();
        blocks.insert(p1.blake3, b1);
        blocks.insert(p2.blake3, b2);

        let mut segs = BTreeMap::new();
        let mut locs = BTreeMap::new();
        write_cold_segments_for_blocks(&dir, &mut segs, &mut locs, blocks).unwrap();
        assert_eq!(segs.len(), 1);
        assert_eq!(locs.len(), 2);

        let dir_entries: Vec<ColdSegmentDirEntryV1> = segs
            .iter()
            .map(|(segment_blake3, file_len)| ColdSegmentDirEntryV1 {
                segment_blake3: *segment_blake3,
                file_len: *file_len,
            })
            .collect();
        let (segs2, locs2) = load_cold_segment_indexes(&dir, &dir_entries).unwrap();
        assert_eq!(segs2, segs);
        assert_eq!(locs2.len(), 2);
        assert!(locs2.contains_key(&p1.blake3));
        assert!(locs2.contains_key(&p2.blake3));
    }

    #[test]
    fn load_cold_segment_indexes_empty_dir_yields_empty_maps() {
        let tmp = TempDir::new().unwrap();
        let (segs, locs) = load_cold_segment_indexes(tmp.path(), &[]).unwrap();
        assert!(segs.is_empty());
        assert!(locs.is_empty());
    }

    #[test]
    fn load_cold_segment_indexes_duplicate_segment_id_errors() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("segments");
        std::fs::create_dir_all(&dir).unwrap();
        let (bytes, ptr) = relations_block(1, 1);
        let mut blocks = BTreeMap::new();
        blocks.insert(ptr.blake3, bytes);
        let (seg_bytes, seg_blake3, _idx) = build_cold_segment_v1(&blocks);
        ensure_cold_segment_written(&dir, &seg_blake3, &seg_bytes).unwrap();

        let entry = ColdSegmentDirEntryV1 {
            segment_blake3: seg_blake3,
            file_len: seg_bytes.len() as u64,
        };
        let err = load_cold_segment_indexes(&dir, &[entry, entry]).unwrap_err();
        assert!(
            format!("{err}").contains("duplicate segment id"),
            "unexpected error: {err}"
        );
    }

    /// A dir entry naming a segment file that is not on disk must surface as an
    /// error, never as "no blocks found".
    #[test]
    fn load_cold_segment_indexes_missing_segment_file_errors() {
        let tmp = TempDir::new().unwrap();
        let entry = ColdSegmentDirEntryV1 {
            segment_blake3: [0x22; 32],
            file_len: 4_096,
        };
        assert!(load_cold_segment_indexes(tmp.path(), &[entry]).is_err());
    }

    /// Two distinct segments carrying the same content-addressed block make the
    /// block -> location mapping ambiguous; that must be rejected rather than
    /// silently resolved last-writer-wins.
    #[test]
    fn load_cold_segment_indexes_duplicate_block_across_segments_errors() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("segments");
        std::fs::create_dir_all(&dir).unwrap();

        let (b1, p1) = relations_block(3, 1);
        let (b2, p2) = relations_block(3, 2);

        let mut only_first = BTreeMap::new();
        only_first.insert(p1.blake3, b1.clone());
        let mut both = BTreeMap::new();
        both.insert(p1.blake3, b1);
        both.insert(p2.blake3, b2);

        let mut entries = Vec::new();
        for blocks in [only_first, both] {
            let (seg_bytes, seg_blake3, _idx) = build_cold_segment_v1(&blocks);
            ensure_cold_segment_written(&dir, &seg_blake3, &seg_bytes).unwrap();
            entries.push(ColdSegmentDirEntryV1 {
                segment_blake3: seg_blake3,
                file_len: seg_bytes.len() as u64,
            });
        }

        let err = load_cold_segment_indexes(&dir, &entries).unwrap_err();
        assert!(
            format!("{err}").contains("duplicate block blake3"),
            "unexpected error: {err}"
        );
    }

    // ── ensure_cold_segment_written ─────────────────────────────────

    /// Content-addressed segments are never rewritten. Pins that an existing
    /// file short-circuits the write, so a concurrent publisher cannot be
    /// clobbered mid-read.
    #[test]
    fn ensure_cold_segment_written_does_not_rewrite_existing_path() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("segments");
        std::fs::create_dir_all(&dir).unwrap();
        let id = [0x77u8; 32];
        let path = cold_segment_path_v1(&dir, &id);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"original").unwrap();

        let out = ensure_cold_segment_written(&dir, &id, b"replacement bytes").unwrap();
        assert_eq!(out, path);
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
    }

    // ── load_relations_from_cold_blocks (schema v2) ─────────────────

    #[test]
    fn load_relations_from_cold_blocks_round_trips() {
        let tmp = TempDir::new().unwrap();
        let files = files_in(&tmp);
        let (bytes, ptr) = relations_block(5, 42);
        write_cold_block(&files.cold_relations_dir, &ptr.blake3, &bytes);

        let mut ptrs = BTreeMap::new();
        ptrs.insert((5u64, 42u32), ptr.clone());
        let edges = load_relations_from_cold_blocks(&files, &ptrs).unwrap();
        assert_eq!(edges.len(), 2);
        assert!(edges.keys().all(|k| k.0 == 5 && k.1 == 42));
    }

    #[test]
    fn load_relations_from_cold_blocks_missing_file_errors() {
        let tmp = TempDir::new().unwrap();
        let files = files_in(&tmp);
        let (_bytes, ptr) = relations_block(5, 42);
        let mut ptrs = BTreeMap::new();
        ptrs.insert((5u64, 42u32), ptr.clone());
        assert!(load_relations_from_cold_blocks(&files, &ptrs).is_err());
    }

    /// A truncated block file must be reported, not decoded to a shorter edge
    /// list that would silently drop relations.
    #[test]
    fn load_relations_from_cold_blocks_truncated_block_errors() {
        let tmp = TempDir::new().unwrap();
        let files = files_in(&tmp);
        let (bytes, ptr) = relations_block(5, 42);
        write_cold_block(
            &files.cold_relations_dir,
            &ptr.blake3,
            &bytes[..RELATION_EDGE_STRIDE_V1],
        );

        let mut ptrs = BTreeMap::new();
        ptrs.insert((5u64, 42u32), ptr.clone());
        let err = load_relations_from_cold_blocks(&files, &ptrs).unwrap_err();
        assert!(format!("{err}").contains("length mismatch"), "unexpected error: {err}");
    }

    /// Same length, different bytes: only the blake3 check can catch this.
    #[test]
    fn load_relations_from_cold_blocks_hash_mismatch_errors() {
        let tmp = TempDir::new().unwrap();
        let files = files_in(&tmp);
        let (mut bytes, ptr) = relations_block(5, 42);
        bytes[RELATION_EDGE_STRIDE_V1 - 1] ^= 0xFF;
        write_cold_block(&files.cold_relations_dir, &ptr.blake3, &bytes);

        let mut ptrs = BTreeMap::new();
        ptrs.insert((5u64, 42u32), ptr.clone());
        let err = load_relations_from_cold_blocks(&files, &ptrs).unwrap_err();
        assert!(format!("{err}").contains("hash mismatch"), "unexpected error: {err}");
    }

    /// A block whose contents belong to a different `(tenant, src)` than the
    /// hot pointer claims would leak edges across tenants if accepted.
    #[test]
    fn load_relations_from_cold_blocks_wrong_tenant_keys_error() {
        let tmp = TempDir::new().unwrap();
        let files = files_in(&tmp);
        let (bytes, ptr) = relations_block(5, 42);
        write_cold_block(&files.cold_relations_dir, &ptr.blake3, &bytes);

        // Same block, but filed under a different tenant/src in the hot ptrs.
        let mut ptrs = BTreeMap::new();
        ptrs.insert((6u64, 42u32), ptr.clone());
        let err = load_relations_from_cold_blocks(&files, &ptrs).unwrap_err();
        assert!(
            format!("{err}").contains("wrong tenant_hash/src keys"),
            "unexpected error: {err}"
        );
    }

    // ── load_dependents_from_cold_blocks (schema v2) ────────────────

    #[test]
    fn load_dependents_from_cold_blocks_round_trips() {
        let tmp = TempDir::new().unwrap();
        let files = files_in(&tmp);
        let (bytes, ptr) = dependents_block(8, 3);
        write_cold_block(&files.cold_dependents_dir, &ptr.blake3, &bytes);

        let mut ptrs = BTreeMap::new();
        ptrs.insert((8u64, 3u32), ptr.clone());
        let edges = load_dependents_from_cold_blocks(&files, &ptrs).unwrap();
        assert_eq!(edges.len(), 1);
    }

    #[test]
    fn load_dependents_from_cold_blocks_truncated_block_errors() {
        let tmp = TempDir::new().unwrap();
        let files = files_in(&tmp);
        let (bytes, ptr) = dependents_block(8, 3);
        write_cold_block(&files.cold_dependents_dir, &ptr.blake3, &bytes[..8]);

        let mut ptrs = BTreeMap::new();
        ptrs.insert((8u64, 3u32), ptr.clone());
        let err = load_dependents_from_cold_blocks(&files, &ptrs).unwrap_err();
        assert!(format!("{err}").contains("length mismatch"), "unexpected error: {err}");
    }

    #[test]
    fn load_dependents_from_cold_blocks_hash_mismatch_errors() {
        let tmp = TempDir::new().unwrap();
        let files = files_in(&tmp);
        let (mut bytes, ptr) = dependents_block(8, 3);
        bytes[DEPENDENT_EDGE_STRIDE_V1 - 1] ^= 0xFF;
        write_cold_block(&files.cold_dependents_dir, &ptr.blake3, &bytes);

        let mut ptrs = BTreeMap::new();
        ptrs.insert((8u64, 3u32), ptr.clone());
        let err = load_dependents_from_cold_blocks(&files, &ptrs).unwrap_err();
        assert!(format!("{err}").contains("hash mismatch"), "unexpected error: {err}");
    }

    #[test]
    fn load_dependents_from_cold_blocks_wrong_artifact_keys_error() {
        let tmp = TempDir::new().unwrap();
        let files = files_in(&tmp);
        let (bytes, ptr) = dependents_block(8, 3);
        write_cold_block(&files.cold_dependents_dir, &ptr.blake3, &bytes);

        let mut ptrs = BTreeMap::new();
        ptrs.insert((8u64, 4u32), ptr.clone());
        let err = load_dependents_from_cold_blocks(&files, &ptrs).unwrap_err();
        assert!(
            format!("{err}").contains("wrong tenant_hash/artifact_id keys"),
            "unexpected error: {err}"
        );
    }

    // ── load_*_from_cold_segments (schema v3) ───────────────────────

    /// Build a one-block segment on disk under `segments_dir` and return the
    /// location record for it.
    fn write_single_block_segment(segments_dir: &Path, block_hash: [u8; 32], bytes: &[u8]) -> ColdBlockLocV1 {
        let mut blocks = BTreeMap::new();
        blocks.insert(block_hash, bytes.to_vec());
        let (seg_bytes, seg_blake3, idx) = build_cold_segment_v1(&blocks);
        ensure_cold_segment_written(segments_dir, &seg_blake3, &seg_bytes).unwrap();
        let e = idx.first().unwrap();
        ColdBlockLocV1 {
            segment_blake3: seg_blake3,
            offset: e.offset,
            len: e.len,
            codec: e.codec,
        }
    }

    #[test]
    fn load_relations_from_cold_segments_round_trips() {
        let tmp = TempDir::new().unwrap();
        let files = files_in(&tmp);
        let (bytes, ptr) = relations_block(2, 9);
        let loc = write_single_block_segment(&files.cold_relations_segments_dir, ptr.blake3, &bytes);

        let mut ptrs = BTreeMap::new();
        ptrs.insert((2u64, 9u32), ptr.clone());
        let mut locs = BTreeMap::new();
        locs.insert(ptr.blake3, loc);

        let edges = load_relations_from_cold_segments(&files, &ptrs, &locs).unwrap();
        assert_eq!(edges.len(), 2);
    }

    #[test]
    fn load_relations_from_cold_segments_missing_loc_errors() {
        let tmp = TempDir::new().unwrap();
        let files = files_in(&tmp);
        let (_bytes, ptr) = relations_block(2, 9);
        let mut ptrs = BTreeMap::new();
        ptrs.insert((2u64, 9u32), ptr.clone());
        let err = load_relations_from_cold_segments(&files, &ptrs, &BTreeMap::new()).unwrap_err();
        assert!(
            format!("{err}").contains("missing cold block loc"),
            "unexpected error: {err}"
        );
    }

    /// The hot pointer's `block_len` and the segment index's `len` must agree;
    /// a disagreement means one of the two is stale.
    #[test]
    fn load_relations_from_cold_segments_len_disagreement_errors() {
        let tmp = TempDir::new().unwrap();
        let files = files_in(&tmp);
        let (bytes, ptr) = relations_block(2, 9);
        let mut loc = write_single_block_segment(&files.cold_relations_segments_dir, ptr.blake3, &bytes);
        loc.len = loc.len.saturating_sub(RELATION_EDGE_STRIDE_V1 as u32);

        let mut ptrs = BTreeMap::new();
        ptrs.insert((2u64, 9u32), ptr.clone());
        let mut locs = BTreeMap::new();
        locs.insert(ptr.blake3, loc);

        let err = load_relations_from_cold_segments(&files, &ptrs, &locs).unwrap_err();
        assert!(
            format!("{err}").contains("block_len != cold block loc len"),
            "unexpected error: {err}"
        );
    }

    /// Bytes stored under a block id that does not hash to them: the segment
    /// index is intact but the payload is not what it claims to be.
    #[test]
    fn load_relations_from_cold_segments_hash_mismatch_errors() {
        let tmp = TempDir::new().unwrap();
        let files = files_in(&tmp);
        let (mut bytes, ptr) = relations_block(2, 9);
        bytes[0] ^= 0xFF;
        let loc = write_single_block_segment(&files.cold_relations_segments_dir, ptr.blake3, &bytes);

        let mut ptrs = BTreeMap::new();
        ptrs.insert((2u64, 9u32), ptr.clone());
        let mut locs = BTreeMap::new();
        locs.insert(ptr.blake3, loc);

        let err = load_relations_from_cold_segments(&files, &ptrs, &locs).unwrap_err();
        assert!(format!("{err}").contains("hash mismatch"), "unexpected error: {err}");
    }

    #[test]
    fn load_dependents_from_cold_segments_round_trips() {
        let tmp = TempDir::new().unwrap();
        let files = files_in(&tmp);
        let (bytes, ptr) = dependents_block(4, 6);
        let loc = write_single_block_segment(&files.cold_dependents_segments_dir, ptr.blake3, &bytes);

        let mut ptrs = BTreeMap::new();
        ptrs.insert((4u64, 6u32), ptr.clone());
        let mut locs = BTreeMap::new();
        locs.insert(ptr.blake3, loc);

        let edges = load_dependents_from_cold_segments(&files, &ptrs, &locs).unwrap();
        assert_eq!(edges.len(), 1);
    }

    #[test]
    fn load_dependents_from_cold_segments_missing_loc_errors() {
        let tmp = TempDir::new().unwrap();
        let files = files_in(&tmp);
        let (_bytes, ptr) = dependents_block(4, 6);
        let mut ptrs = BTreeMap::new();
        ptrs.insert((4u64, 6u32), ptr.clone());
        let err = load_dependents_from_cold_segments(&files, &ptrs, &BTreeMap::new()).unwrap_err();
        assert!(
            format!("{err}").contains("missing cold block loc"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn load_dependents_from_cold_segments_len_disagreement_errors() {
        let tmp = TempDir::new().unwrap();
        let files = files_in(&tmp);
        let (bytes, ptr) = dependents_block(4, 6);
        let mut loc = write_single_block_segment(&files.cold_dependents_segments_dir, ptr.blake3, &bytes);
        loc.len = loc.len.saturating_add(1);

        let mut ptrs = BTreeMap::new();
        ptrs.insert((4u64, 6u32), ptr.clone());
        let mut locs = BTreeMap::new();
        locs.insert(ptr.blake3, loc);

        let err = load_dependents_from_cold_segments(&files, &ptrs, &locs).unwrap_err();
        assert!(
            format!("{err}").contains("block_len != cold block loc len"),
            "unexpected error: {err}"
        );
    }

    // ── reachable_cold_segments_from_snapshot_v1 ────────────────────

    fn write_relations_snapshot_v3(path: &Path, segs: &BTreeMap<[u8; 32], u64>) -> String {
        let snap = CcxsnapSnapshot {
            header: CcxsnapSnapshotHeaderV1 {
                projection_id: CcxsnapProjectionId::ArtifactRelations,
                schema_version: 3,
                created_at_unix_ns: 0,
                shard_id: 1,
                epoch: 1,
                cursor_segment_seq: 0,
                cursor_offset: 0,
                block_count: 2,
                codec: CCXSNAP_CODEC_NONE,
            },
            blocks: vec![
                (CCXSNAP_BLOCK_HOT_PTRS_V1, encode_hot_ptrs_v1(&BTreeMap::new())),
                (CCXSNAP_BLOCK_COLD_SEGMENT_DIR_V1, encode_cold_segment_dir_v1(segs)),
            ],
        };
        let bytes = snap.encode().unwrap();
        write_atomic(path, &bytes).unwrap();
        CcxsnapSnapshot::snapshot_blake3_hex(&bytes)
    }

    #[test]
    fn reachable_cold_segments_schema_below_v3_is_unknown() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("relations.ccxsnap");
        assert!(reachable_cold_segments_from_snapshot_v1(&path, 2, Some("deadbeef"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn reachable_cold_segments_without_expected_hash_is_unknown() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("relations.ccxsnap");
        assert!(reachable_cold_segments_from_snapshot_v1(&path, 3, None)
            .unwrap()
            .is_none());
    }

    /// Meta claims a snapshot hash but the snapshot file is gone: that is a
    /// hard error, not "nothing is reachable" (which would make GC delete
    /// every live segment).
    #[test]
    fn reachable_cold_segments_missing_snapshot_file_errors() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("relations.ccxsnap");
        let err = reachable_cold_segments_from_snapshot_v1(&path, 3, Some(&"a".repeat(64))).unwrap_err();
        assert!(
            format!("{err}").contains("snapshot missing but"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn reachable_cold_segments_hash_mismatch_errors() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("relations.ccxsnap");
        let mut segs = BTreeMap::new();
        segs.insert([0x31u8; 32], 99u64);
        let _hash = write_relations_snapshot_v3(&path, &segs);
        let err = reachable_cold_segments_from_snapshot_v1(&path, 3, Some(&"b".repeat(64))).unwrap_err();
        assert!(
            format!("{err}").contains("snapshot blake3 mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn reachable_cold_segments_missing_dir_block_errors() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("relations.ccxsnap");
        let snap = CcxsnapSnapshot {
            header: CcxsnapSnapshotHeaderV1 {
                projection_id: CcxsnapProjectionId::ArtifactRelations,
                schema_version: 3,
                created_at_unix_ns: 0,
                shard_id: 1,
                epoch: 1,
                cursor_segment_seq: 0,
                cursor_offset: 0,
                block_count: 1,
                codec: CCXSNAP_CODEC_NONE,
            },
            blocks: vec![(CCXSNAP_BLOCK_HOT_PTRS_V1, encode_hot_ptrs_v1(&BTreeMap::new()))],
        };
        let bytes = snap.encode().unwrap();
        write_atomic(&path, &bytes).unwrap();
        let hash = CcxsnapSnapshot::snapshot_blake3_hex(&bytes);
        let err = reachable_cold_segments_from_snapshot_v1(&path, 3, Some(&hash)).unwrap_err();
        assert!(
            format!("{err}").contains("missing cold segment dir block"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn reachable_cold_segments_reads_dir_block() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("relations.ccxsnap");
        let mut segs = BTreeMap::new();
        segs.insert([0x41u8; 32], 1_024u64);
        segs.insert([0x42u8; 32], 2_048u64);
        let hash = write_relations_snapshot_v3(&path, &segs);

        let out = reachable_cold_segments_from_snapshot_v1(&path, 3, Some(&hash))
            .unwrap()
            .unwrap();
        assert_eq!(out, segs);
    }

    // ── gc_cold_segments_dir_v1 ─────────────────────────────────────

    fn gc_opts(dry_run: bool, min_age_seconds: u64, max_delete: u64) -> ColdSegmentGcOptionsV1 {
        ColdSegmentGcOptionsV1 {
            dry_run,
            min_age_seconds,
            max_delete,
        }
    }

    fn touch_segment(dir: &Path, id: [u8; 32], len: usize) -> PathBuf {
        let path = cold_segment_path_v1(dir, &id);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, vec![0xEEu8; len]).unwrap();
        path
    }

    /// Reachability unknown (schema<3 or missing snapshot) must produce a
    /// `skipped` report with a reason. It counts what is on disk but deletes
    /// nothing — the caller must be able to tell "verified clean" apart from
    /// "could not check".
    #[test]
    fn gc_cold_segments_dir_reports_skipped_when_reachability_unknown() {
        let tmp = TempDir::new().unwrap();
        touch_segment(tmp.path(), [0x01; 32], 16);
        touch_segment(tmp.path(), [0x02; 32], 16);

        let (report, deleted) =
            gc_cold_segments_dir_v1("relations", 2, tmp.path(), None, &gc_opts(false, 0, 0)).unwrap();
        assert!(report.skipped);
        assert!(report.skip_reason.is_some());
        assert_eq!(report.segments_on_disk, 2);
        assert_eq!(report.deleted_segments, 0);
        assert_eq!(report.reachable_segments, 0);
        assert!(deleted.is_empty());
        // Nothing was removed.
        assert_eq!(collect_files_recursive_v1(tmp.path()).unwrap().len(), 2);
    }

    /// D-28 (pin inverted): a segments directory that does not exist used to
    /// yield an all-zero, `skipped:false` report — "nothing on disk, nothing
    /// orphaned" — indistinguishable from a directory that was scanned and
    /// found clean, because `collect_files_recursive_v1` swallows the read_dir
    /// error. It now reports `skipped:true`, so "could not look" is a distinct
    /// answer from "looked and found nothing".
    #[test]
    fn gc_cold_segments_dir_missing_directory_reports_skipped_not_clean() {
        let tmp = TempDir::new().unwrap();
        let missing = tmp.path().join("does-not-exist");
        let reachable = BTreeMap::new();
        let (report, deleted) =
            gc_cold_segments_dir_v1("relations", 3, &missing, Some(&reachable), &gc_opts(false, 0, 0)).unwrap();
        assert!(report.skipped, "a directory that could not be read is not a clean scan");
        assert_eq!(report.segments_on_disk, 0);
        assert_eq!(report.orphan_segments, 0);
        assert_eq!(report.unparseable_segment_files, 0);
        assert!(deleted.is_empty());
    }

    #[test]
    fn gc_cold_segments_dir_ignores_non_segment_extensions() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("notes.txt"), b"hello").unwrap();
        std::fs::write(tmp.path().join("block.ccxblk"), b"hello").unwrap();
        let reachable = BTreeMap::new();
        let (report, deleted) =
            gc_cold_segments_dir_v1("relations", 3, tmp.path(), Some(&reachable), &gc_opts(false, 0, 0)).unwrap();
        assert_eq!(report.segments_on_disk, 0);
        assert!(deleted.is_empty());
        assert_eq!(collect_files_recursive_v1(tmp.path()).unwrap().len(), 2);
    }

    /// A `.ccxcseg` whose stem is not a blake3 hex id is counted as
    /// unparsable and left alone rather than deleted on a guess.
    #[test]
    fn gc_cold_segments_dir_counts_unparsable_stem_and_keeps_file() {
        let tmp = TempDir::new().unwrap();
        let bad = tmp.path().join("not-a-hash.ccxcseg");
        std::fs::write(&bad, b"junk").unwrap();
        let reachable = BTreeMap::new();
        let (report, deleted) =
            gc_cold_segments_dir_v1("relations", 3, tmp.path(), Some(&reachable), &gc_opts(false, 0, 0)).unwrap();
        assert_eq!(report.segments_on_disk, 1);
        assert_eq!(report.unparseable_segment_files, 1);
        assert_eq!(report.orphan_segments, 0);
        assert_eq!(report.deleted_segments, 0);
        assert!(deleted.is_empty());
        assert!(bad.exists());
    }

    #[test]
    fn gc_cold_segments_dir_keeps_reachable_and_deletes_orphans() {
        let tmp = TempDir::new().unwrap();
        let keep = [0xA1u8; 32];
        let drop_id = [0xB2u8; 32];
        let keep_path = touch_segment(tmp.path(), keep, 32);
        let drop_path = touch_segment(tmp.path(), drop_id, 64);

        let mut reachable = BTreeMap::new();
        reachable.insert(keep, 32u64);

        let (report, deleted) =
            gc_cold_segments_dir_v1("relations", 3, tmp.path(), Some(&reachable), &gc_opts(false, 0, 0)).unwrap();
        assert_eq!(report.segments_on_disk, 2);
        assert_eq!(report.reachable_segments, 1);
        assert_eq!(report.orphan_segments, 1);
        assert_eq!(report.deleted_segments, 1);
        assert_eq!(report.deleted_bytes, 64);
        assert!(deleted.contains(&drop_id));
        assert!(keep_path.exists());
        assert!(!drop_path.exists());
    }

    /// Dry-run must report exactly what it *would* delete while leaving the
    /// files in place.
    #[test]
    fn gc_cold_segments_dir_dry_run_reports_without_deleting() {
        let tmp = TempDir::new().unwrap();
        let orphan = [0xC3u8; 32];
        let path = touch_segment(tmp.path(), orphan, 128);
        let reachable = BTreeMap::new();

        let (report, deleted) =
            gc_cold_segments_dir_v1("dependents", 3, tmp.path(), Some(&reachable), &gc_opts(true, 0, 0)).unwrap();
        assert_eq!(report.orphan_segments, 1);
        assert_eq!(report.deleted_segments, 1);
        assert_eq!(report.deleted_bytes, 128);
        assert!(deleted.contains(&orphan));
        assert!(path.exists(), "dry run must not remove the file");
    }

    #[test]
    fn gc_cold_segments_dir_respects_max_delete_limit() {
        let tmp = TempDir::new().unwrap();
        for i in 0..4u8 {
            touch_segment(tmp.path(), [0xD0 | i; 32], 8);
        }
        let reachable = BTreeMap::new();
        let (report, deleted) =
            gc_cold_segments_dir_v1("relations", 3, tmp.path(), Some(&reachable), &gc_opts(false, 0, 2)).unwrap();
        assert_eq!(report.orphan_segments, 4);
        assert_eq!(report.deleted_segments, 2);
        assert_eq!(report.kept_orphans_due_to_limit, 2);
        assert_eq!(deleted.len(), 2);
        assert_eq!(collect_files_recursive_v1(tmp.path()).unwrap().len(), 2);
    }

    /// Freshly written orphans are within `min_age_seconds` and must be held
    /// back — deleting a segment a concurrent commit just published would
    /// corrupt the projection.
    #[test]
    fn gc_cold_segments_dir_skips_young_orphans() {
        let tmp = TempDir::new().unwrap();
        let orphan = [0xE4u8; 32];
        let path = touch_segment(tmp.path(), orphan, 16);
        let reachable = BTreeMap::new();
        let (report, deleted) =
            gc_cold_segments_dir_v1("relations", 3, tmp.path(), Some(&reachable), &gc_opts(false, 86_400, 0)).unwrap();
        assert_eq!(report.orphan_segments, 1);
        assert_eq!(report.skipped_young_segments, 1);
        assert_eq!(report.deleted_segments, 0);
        assert!(deleted.is_empty());
        assert!(path.exists());
    }

    // ── ProjectionStoreV1::gc_orphan_cold_segments_v1 ───────────────

    /// After GC the store's hot pointers must still resolve. A dangling
    /// pointer under schema v3 is an error, not a silently degraded store.
    #[test]
    fn gc_orphan_cold_segments_errors_on_dangling_relations_hot_ptr() {
        let tmp = TempDir::new().unwrap();
        let shard_dir = tmp.path().join("shard-0001");
        std::fs::create_dir_all(&shard_dir).unwrap();
        let mut store = ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        store.meta.artifact_relations.schema_version = 3;
        store.meta.artifact_relations.snapshot_blake3 = None; // reachability unknown -> skip
        let (_bytes, ptr) = relations_block(1, 1);
        store.relations_hot_ptrs.insert((1, 1), ptr);

        let err = store.gc_orphan_cold_segments_v1(gc_opts(true, 0, 0)).unwrap_err();
        assert!(
            format!("{err}").contains("relations hot ptr references missing cold block loc"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn gc_orphan_cold_segments_errors_on_dangling_dependents_hot_ptr() {
        let tmp = TempDir::new().unwrap();
        let shard_dir = tmp.path().join("shard-0001");
        std::fs::create_dir_all(&shard_dir).unwrap();
        let mut store = ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        store.meta.artifact_dependents.schema_version = 3;
        store.meta.artifact_dependents.snapshot_blake3 = None;
        let (_bytes, ptr) = dependents_block(1, 1);
        store.dependents_hot_ptrs.insert((1, 1), ptr);

        let err = store.gc_orphan_cold_segments_v1(gc_opts(true, 0, 0)).unwrap_err();
        assert!(
            format!("{err}").contains("dependents hot ptr references missing cold block loc"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn gc_orphan_cold_segments_on_fresh_store_reports_both_projections_skipped() {
        let tmp = TempDir::new().unwrap();
        let shard_dir = tmp.path().join("shard-0001");
        std::fs::create_dir_all(&shard_dir).unwrap();
        let mut store = ProjectionStoreV1::load_or_init(&shard_dir, 3, 9).unwrap();
        let report = store.gc_orphan_cold_segments_v1(gc_opts(true, 60, 5)).unwrap();
        assert_eq!(report.shard_id, 3);
        assert_eq!(report.epoch, 9);
        assert!(report.dry_run);
        assert_eq!(report.min_age_seconds, 60);
        assert_eq!(report.max_delete, 5);
        assert!(report.relations.skipped);
        assert!(report.dependents.skipped);
        assert_eq!(report.relations.projection, "relations");
        assert_eq!(report.dependents.projection, "dependents");
    }

    // ── decode_frame_projection_inputs ──────────────────────────────

    #[test]
    fn decode_frame_projection_inputs_rejects_garbage_bytes() {
        assert!(decode_frame_projection_inputs(&[0u8; 64]).is_err());
    }

    /// A frame whose header region is shorter than the 32-byte trailing header
    /// hash cannot be split into (canonical, hash); reject rather than index
    /// out of bounds or read a truncated canonical header.
    #[test]
    fn decode_frame_projection_inputs_rejects_short_header() {
        let frame = corecrux_segment::encode_frame_v1(&[0u8; 8], b"payload").unwrap();
        let err = decode_frame_projection_inputs(&frame).unwrap_err();
        assert!(
            matches!(&err, ProjectionError::InvalidFrameHeader { msg } if msg.contains("too small")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn decode_frame_projection_inputs_rejects_undecodable_canonical_header() {
        let frame = corecrux_segment::encode_frame_v1(&[0xFFu8; 96], b"payload").unwrap();
        let err = decode_frame_projection_inputs(&frame).unwrap_err();
        assert!(
            matches!(&err, ProjectionError::InvalidFrameHeader { msg } if msg.contains("canonical header decode failed")),
            "unexpected error: {err}"
        );
    }

    // ── ProjectionStoreV1::load_or_init recovery paths ──────────────

    /// A living-state snapshot whose bytes no longer hash to the value recorded
    /// in `projections.meta.json` must reset meta AND state, so the next tick
    /// replays from genesis instead of resuming on top of a corrupt snapshot.
    #[test]
    fn load_or_init_snapshot_hash_mismatch_resets_meta_to_genesis() {
        let tmp = TempDir::new().unwrap();
        let shard_dir = tmp.path().join("shard-0001");
        std::fs::create_dir_all(&shard_dir).unwrap();
        let files = ProjectionFilesV1::for_shard_dir(&shard_dir);
        std::fs::create_dir_all(&files.projections_dir).unwrap();

        let mut meta = crate::meta::ProjectionsMetaV1::empty_now();
        meta.commit_id = 17;
        meta.artifact_living_state.snapshot_blake3 = Some("c".repeat(64));
        meta.artifact_living_state.cursor = Some(ProjectionCursorV1 {
            shard_id: 1,
            epoch: 1,
            segment_seq: 4,
            offset: 900,
        });
        store_projections_meta_v1(&files.meta_path, &meta).unwrap();
        std::fs::write(&files.living_snapshot_path, b"not the recorded snapshot").unwrap();

        let store = ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        assert_eq!(store.meta.commit_id, 0, "meta must be reset to genesis");
        assert!(store.meta.artifact_living_state.cursor.is_none());
        assert!(store.meta.artifact_living_state.snapshot_blake3.is_none());
        assert!(store.state.living.is_empty());
        assert!(store.cursor_from_meta().is_none());
    }

    /// A snapshot whose recorded hash matches but whose body is not a decodable
    /// `.ccxsnap` container is equally a reset, not a partial load.
    #[test]
    fn load_or_init_undecodable_snapshot_resets_meta_to_genesis() {
        let tmp = TempDir::new().unwrap();
        let shard_dir = tmp.path().join("shard-0001");
        std::fs::create_dir_all(&shard_dir).unwrap();
        let files = ProjectionFilesV1::for_shard_dir(&shard_dir);
        std::fs::create_dir_all(&files.projections_dir).unwrap();

        let garbage = b"CSNP-ish but not really".to_vec();
        let mut meta = crate::meta::ProjectionsMetaV1::empty_now();
        meta.commit_id = 5;
        meta.artifact_living_state.snapshot_blake3 = Some(CcxsnapSnapshot::snapshot_blake3_hex(&garbage));
        store_projections_meta_v1(&files.meta_path, &meta).unwrap();
        std::fs::write(&files.living_snapshot_path, &garbage).unwrap();

        let store = ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        assert_eq!(store.meta.commit_id, 0);
        assert!(store.state.living.is_empty());
    }

    /// An unknown relations `schemaVersion` is a hard error rather than a
    /// silent reset: the operator must be told the binary is too old.
    #[test]
    fn load_or_init_unsupported_relations_schema_version_errors() {
        let tmp = TempDir::new().unwrap();
        let shard_dir = tmp.path().join("shard-0001");
        std::fs::create_dir_all(&shard_dir).unwrap();
        let files = ProjectionFilesV1::for_shard_dir(&shard_dir);
        std::fs::create_dir_all(&files.projections_dir).unwrap();

        let snap = CcxsnapSnapshot {
            header: CcxsnapSnapshotHeaderV1 {
                projection_id: CcxsnapProjectionId::ArtifactRelations,
                schema_version: 99,
                created_at_unix_ns: 0,
                shard_id: 1,
                epoch: 1,
                cursor_segment_seq: 0,
                cursor_offset: 0,
                block_count: 1,
                codec: CCXSNAP_CODEC_NONE,
            },
            blocks: vec![(CCXSNAP_BLOCK_EDGES_V1, Vec::new())],
        };
        let bytes = snap.encode().unwrap();
        std::fs::write(&files.relations_snapshot_path, &bytes).unwrap();

        let mut meta = crate::meta::ProjectionsMetaV1::empty_now();
        meta.artifact_relations.schema_version = 99;
        meta.artifact_relations.snapshot_blake3 = Some(CcxsnapSnapshot::snapshot_blake3_hex(&bytes));
        store_projections_meta_v1(&files.meta_path, &meta).unwrap();

        let Err(err) = ProjectionStoreV1::load_or_init(&shard_dir, 1, 1) else {
            panic!("expected an unsupported-schema error");
        };
        assert!(
            format!("{err}").contains("unsupported relations schema_version 99"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn load_or_init_unsupported_dependents_schema_version_errors() {
        let tmp = TempDir::new().unwrap();
        let shard_dir = tmp.path().join("shard-0001");
        std::fs::create_dir_all(&shard_dir).unwrap();
        let files = ProjectionFilesV1::for_shard_dir(&shard_dir);
        std::fs::create_dir_all(&files.projections_dir).unwrap();

        let snap = CcxsnapSnapshot {
            header: CcxsnapSnapshotHeaderV1 {
                projection_id: CcxsnapProjectionId::ArtifactDependents,
                schema_version: 42,
                created_at_unix_ns: 0,
                shard_id: 1,
                epoch: 1,
                cursor_segment_seq: 0,
                cursor_offset: 0,
                block_count: 1,
                codec: CCXSNAP_CODEC_NONE,
            },
            blocks: vec![(CCXSNAP_BLOCK_EDGES_V1, Vec::new())],
        };
        let bytes = snap.encode().unwrap();
        std::fs::write(&files.dependents_snapshot_path, &bytes).unwrap();

        let mut meta = crate::meta::ProjectionsMetaV1::empty_now();
        meta.artifact_dependents.schema_version = 42;
        meta.artifact_dependents.snapshot_blake3 = Some(CcxsnapSnapshot::snapshot_blake3_hex(&bytes));
        store_projections_meta_v1(&files.meta_path, &meta).unwrap();

        let Err(err) = ProjectionStoreV1::load_or_init(&shard_dir, 1, 1) else {
            panic!("expected an unsupported-schema error");
        };
        assert!(
            format!("{err}").contains("unsupported dependents schema_version 42"),
            "unexpected error: {err}"
        );
    }

    /// DEFECT PIN (absent signal reads as pass): when `projections.meta.json`
    /// records a `snapshotBlake3` and an advanced cursor but the snapshot FILE
    /// is missing, the `.filter(|_| path.exists())` guard at
    /// `load_or_init` skips the whole verification block, leaves `ok = true`,
    /// and the store is returned with the cursor INTACT and state EMPTY. The
    /// next `tick` therefore resumes past frames it never applied. A deleted
    /// snapshot is indistinguishable from a clean load. Reported, not fixed;
    /// this test pins current behaviour so a fix is a deliberate change.
    #[test]
    fn load_or_init_missing_snapshot_file_keeps_cursor_with_empty_state() {
        let tmp = TempDir::new().unwrap();
        let shard_dir = tmp.path().join("shard-0001");
        std::fs::create_dir_all(&shard_dir).unwrap();
        let files = ProjectionFilesV1::for_shard_dir(&shard_dir);
        std::fs::create_dir_all(&files.projections_dir).unwrap();

        let mut meta = crate::meta::ProjectionsMetaV1::empty_now();
        meta.commit_id = 12;
        meta.artifact_living_state.snapshot_blake3 = Some("d".repeat(64));
        meta.artifact_living_state.row_count = 500;
        meta.artifact_living_state.cursor = Some(ProjectionCursorV1 {
            shard_id: 1,
            epoch: 1,
            segment_seq: 7,
            offset: 4_096,
        });
        store_projections_meta_v1(&files.meta_path, &meta).unwrap();
        assert!(!files.living_snapshot_path.exists());

        let store = ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        // D-6 (pin inverted): the meta recorded a snapshot hash and an advanced
        // cursor while the snapshot FILE was gone. The old guard skipped
        // verification entirely and returned the store cursor-intact with empty
        // state, so the next `tick` resumed past frames it had never applied —
        // silent data loss. A missing snapshot now resets to genesis, matching
        // how a corrupt one has always been handled.
        assert_eq!(store.meta.commit_id, 0, "a missing snapshot resets meta to genesis");
        assert!(store.state.living.is_empty(), "and no rows were loaded");
        assert!(
            store.cursor_from_meta().is_none(),
            "the cursor must not survive a snapshot that is gone"
        );
    }

    // ── cursor plumbing ─────────────────────────────────────────────

    #[test]
    fn cursor_from_meta_reflects_stored_cursor() {
        let tmp = TempDir::new().unwrap();
        let shard_dir = tmp.path().join("shard-0001");
        std::fs::create_dir_all(&shard_dir).unwrap();
        let mut store = ProjectionStoreV1::load_or_init(&shard_dir, 1, 1).unwrap();
        store.meta.artifact_living_state.cursor = Some(ProjectionCursorV1 {
            shard_id: 1,
            epoch: 1,
            segment_seq: 11,
            offset: 22,
        });
        let cursor = store.cursor_from_meta().unwrap();
        assert_eq!(cursor.segment_seq, 11);
        assert_eq!(cursor.offset, 22);
    }

    #[test]
    fn infer_cursor_after_frames_saturates_on_huge_offset() {
        let loc = corecrux_storage::FrameLocation {
            shard_id: 1,
            epoch: 1,
            segment_seq: 3,
            offset: u64::MAX,
        };
        let frames: ReplayFrames = vec![(loc, vec![0u8; 8])];
        let cursor = infer_cursor_after_frames(&frames).unwrap();
        assert_eq!(cursor.offset, u64::MAX, "saturating_add must not wrap to 7");
    }
}
