// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! CoreCrux v3 Phase 7: Living Objects projections + snapshots + parity harness plumbing.
//!
//! This crate intentionally keeps all projection logic deterministic:
//! - sorted key orders (BTreeMap/BTreeSet)
//! - integer-only state (quantized confidence, unix micros)
//! - stable encoding for snapshot/meta files

mod ccxs;
mod codec_v1;
mod cold_segment_v1;
mod events;
pub mod extraction;
mod meta;
pub mod query;
mod runner;
pub mod session_plans_by_principal;
mod state;

pub use ccxs::CCXS_BLOCK_STATS_V1;
pub use ccxs::{CcxsProjectionId, CcxsSnapshot, CcxsSnapshotHeaderV1, CcxsSnapshotSummary};
pub use ccxs::{CCXS_BLOCK_ADJ_INDEX_V1, CCXS_BLOCK_HOT_PTRS_V1};
pub use events::EntityFactV1;
pub use events::CONTENT_TYPE_PROJ_BIN_V1;
pub use events::{
    parse_projection_event, DependentEvidenceUpsertV1, LivingStateUpdateV1, PressureEventUpsertV1, ProjectionEventV1,
    RelationDeleteV1, RelationUpsertV1,
};
pub use events::{
    EVT_DEPENDENT_EVIDENCE_UPSERT_V1, EVT_LIVING_STATE_UPDATE_V1, EVT_PRESSURE_UPSERT_V1, EVT_RELATION_DELETE_V1,
    EVT_RELATION_UPSERT_V1,
};
// Session-handshake events (M2; master-plan §7.2). Re-export so corecruxd /
// VaultCrux can mint events without reaching into `events` directly.
pub use events::{
    InvocationReceiptedV1, SessionClosedV1, SessionPlanSealedV1, SessionRevokedV1, CONTENT_TYPE_SESSION_BIN_V1,
    EVT_INVOCATION_RECEIPTED_V1, EVT_SESSION_CLOSED_V1, EVT_SESSION_PLAN_SEALED_V1, EVT_SESSION_REVOKED_V1,
};
// CE → Core migration (M8).
pub use events::{CeInstallImportedV1, EVT_CE_INSTALL_IMPORTED_V1};
// Extraction-cache events (stateful-extraction-flywheel M1). Re-exported so
// corecruxd's HTTP layer and VaultCrux-side tooling can mint them without
// reaching into the `extraction` module directly.
pub use extraction::{
    ExtractionCacheCurrentRowV1, ExtractionCacheHitV1, ExtractionCacheInsertV1, ExtractionCacheInvalidateV1,
    ExtractionCacheMaterializer, ExtractionCacheStats, ExtractionConfidenceDeltaV1, ExtractionVerifierScoredV1,
    CONTENT_TYPE_EXTRACTION_JSON_V1, EVT_EXTRACTION_CACHE_HIT_V1, EVT_EXTRACTION_CACHE_INSERT_V1,
    EVT_EXTRACTION_CACHE_INVALIDATE_V1, EVT_EXTRACTION_CONFIDENCE_DELTA_V1, EVT_EXTRACTION_VERIFIER_SCORED_V1,
};
pub use session_plans_by_principal::{PlanEntryV1, PrincipalKey, SessionPlansByPrincipalV1};
// Access to the events module for downstream crates (corecruxd / tests) that
// need to reach event structs + dispatcher together.
pub mod events_api {
    pub use crate::events::*;
}
pub use meta::{
    load_projections_meta_v1, store_projections_meta_v1, ProjectionCursorV1, ProjectionMetaV1, ProjectionsMetaV1,
};
pub use runner::{
    ColdSegmentGcOptionsV1, ColdSegmentGcProjectionReportV1, ColdSegmentGcReportV1, ProjectionFilesV1,
    ProjectionStoreV1, ProjectionsTickResultV1,
};
pub use state::{dequantize_confidence_f32, quantize_confidence_q16};
pub use state::{pressure_code_id_xxhash16, tenant_hash_xxhash64};
pub use state::{
    DependentEdgeV1, DependentTypeV1, EntityCountRowV1, EntityCurrentStateRowV1, EntityTimelineEntryV1,
    LivingStateRowV1, LivingStatusV1, PressureEventRowV1, ProjectionApplyStats, ProjectionState, RelationEdgeV1,
    RelationTypeV1,
};

#[derive(Debug, thiserror::Error)]
pub enum ProjectionError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("segment: {0}")]
    Segment(#[from] corecrux_segment::SegmentError),
    #[error("storage: {0}")]
    Storage(#[from] corecrux_storage::StorageError),
    #[error("invalid frame header bytes: {msg}")]
    InvalidFrameHeader { msg: String },
    #[error("invalid projection event: {msg}")]
    InvalidEvent { msg: String },
    #[error("snapshot: {0}")]
    Snapshot(#[from] ccxs::CcxsError),
    #[error("meta: {0}")]
    Meta(#[from] meta::MetaError),
}

pub type Result<T> = std::result::Result<T, ProjectionError>;

#[cfg(test)]
mod runner_tests;
