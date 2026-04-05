// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MetaError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid meta: {msg}")]
    Invalid { msg: String },
}

pub type Result<T> = std::result::Result<T, MetaError>;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProjectionCursorV1 {
    #[serde(rename = "shardId")]
    pub shard_id: u32,
    pub epoch: u64,
    #[serde(rename = "segmentSeq")]
    pub segment_seq: u64,
    pub offset: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProjectionMetaV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<ProjectionCursorV1>,
    #[serde(rename = "snapshotBlake3", skip_serializing_if = "Option::is_none")]
    pub snapshot_blake3: Option<String>,
    #[serde(rename = "rowCount")]
    pub row_count: u64,
}

impl ProjectionMetaV1 {
    pub fn empty(schema_version: u32) -> Self {
        Self {
            schema_version,
            cursor: None,
            snapshot_blake3: None,
            row_count: 0,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProjectionsMetaV1 {
    pub v: u32,
    #[serde(rename = "commitId")]
    pub commit_id: u64,
    #[serde(rename = "createdAt")]
    pub created_at: String,

    #[serde(rename = "artifactLivingState")]
    pub artifact_living_state: ProjectionMetaV1,
    #[serde(rename = "artifactRelations")]
    pub artifact_relations: ProjectionMetaV1,
    #[serde(rename = "pressureEvents")]
    pub pressure_events: ProjectionMetaV1,
    #[serde(rename = "artifactDependents")]
    pub artifact_dependents: ProjectionMetaV1,
}

impl ProjectionsMetaV1 {
    pub fn empty_now() -> Self {
        Self {
            v: 1,
            commit_id: 0,
            created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            artifact_living_state: ProjectionMetaV1::empty(/*schema_version=*/ 1),
            artifact_relations: ProjectionMetaV1::empty(/*schema_version=*/ 1),
            pressure_events: ProjectionMetaV1::empty(/*schema_version=*/ 1),
            artifact_dependents: ProjectionMetaV1::empty(/*schema_version=*/ 1),
        }
    }
}

pub fn load_projections_meta_v1(path: &Path) -> Result<ProjectionsMetaV1> {
    if !path.exists() {
        return Ok(ProjectionsMetaV1::empty_now());
    }
    let bytes = std::fs::read(path)?;
    let meta: ProjectionsMetaV1 = serde_json::from_slice(&bytes)?;
    if meta.v != 1 {
        return Err(MetaError::Invalid {
            msg: format!("unsupported projections.meta.json version {}", meta.v),
        });
    }
    Ok(meta)
}

pub fn store_projections_meta_v1(path: &Path, meta: &ProjectionsMetaV1) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let tmp = path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
    let bytes = serde_json::to_vec_pretty(meta)?;
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp)?;
    f.write_all(&bytes)?;
    f.flush()?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
