// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use thiserror::Error;

pub const PROJECTION_MODULE_VERSION_SCHEMA_V1: &str = "crux.projection_module_version.v1";
pub const PROJECTION_MODULES_LIST_SCHEMA_V1: &str = "crux.projection_modules.list.v1";

const MODULE_VERSION: &str = env!("CARGO_PKG_VERSION");
const ARTIFACT_LIVING_STATE_MODULE_ID: &str = "corecrux.projections.artifact_living_state";
const ARTIFACT_RELATIONS_MODULE_ID: &str = "corecrux.projections.artifact_relations";
const PRESSURE_EVENTS_MODULE_ID: &str = "corecrux.projections.pressure_events";
const ARTIFACT_DEPENDENTS_MODULE_ID: &str = "corecrux.projections.artifact_dependents";

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
#[serde(rename_all = "snake_case")]
pub enum ProjectionModuleStatusV1 {
    Active,
    RetainedForReplay,
    Deprecated,
    Unavailable,
}

impl ProjectionModuleStatusV1 {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::RetainedForReplay => "retained_for_replay",
            Self::Deprecated => "deprecated",
            Self::Unavailable => "unavailable",
        }
    }

    pub fn replay_available(&self) -> bool {
        matches!(self, Self::Active | Self::RetainedForReplay)
    }
}

fn active_status() -> ProjectionModuleStatusV1 {
    ProjectionModuleStatusV1::Active
}

fn module_schema() -> String {
    PROJECTION_MODULE_VERSION_SCHEMA_V1.to_string()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProjectionModuleVersionV1 {
    #[serde(default = "module_schema")]
    pub schema: String,
    #[serde(rename = "moduleId")]
    pub module_id: String,
    #[serde(rename = "moduleVersion")]
    pub module_version: String,
    #[serde(rename = "codeHash")]
    pub code_hash: String,
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(rename = "configHash")]
    pub config_hash: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "installReceiptId", default, skip_serializing_if = "Option::is_none")]
    pub install_receipt_id: Option<String>,
    #[serde(default = "active_status")]
    pub status: ProjectionModuleStatusV1,
}

impl ProjectionModuleVersionV1 {
    pub fn ref_v1(&self) -> ProjectionModuleRefV1 {
        ProjectionModuleRefV1 {
            module_id: self.module_id.clone(),
            module_version: self.module_version.clone(),
            code_hash: self.code_hash.clone(),
            config_hash: self.config_hash.clone(),
        }
    }

    pub fn matches_ref(
        &self,
        module_id: &str,
        module_version: &str,
        code_hash: Option<&str>,
        config_hash: Option<&str>,
    ) -> bool {
        self.module_id == module_id
            && self.module_version == module_version
            && code_hash.is_none_or(|hash| hash == self.code_hash)
            && config_hash.is_none_or(|hash| hash == self.config_hash)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProjectionModuleRefV1 {
    #[serde(rename = "moduleId")]
    pub module_id: String,
    #[serde(rename = "moduleVersion")]
    pub module_version: String,
    #[serde(rename = "codeHash")]
    pub code_hash: String,
    #[serde(rename = "configHash")]
    pub config_hash: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<ProjectionModuleRefV1>,
}

impl ProjectionMetaV1 {
    pub fn empty(schema_version: u32) -> Self {
        Self {
            schema_version,
            cursor: None,
            snapshot_blake3: None,
            row_count: 0,
            module: None,
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
    #[serde(rename = "projectionModuleRegistry", default)]
    pub projection_module_registry: Vec<ProjectionModuleVersionV1>,
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
            projection_module_registry: Vec::new(),
        }
    }
}

pub fn current_projection_module_versions_v1() -> Vec<ProjectionModuleVersionV1> {
    current_projection_module_versions_at_v1(&chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

pub fn current_projection_module_versions_at_v1(created_at: &str) -> Vec<ProjectionModuleVersionV1> {
    vec![
        module_version(ARTIFACT_LIVING_STATE_MODULE_ID, 1, "hot_rows", created_at),
        module_version(
            ARTIFACT_RELATIONS_MODULE_ID,
            3,
            "hot_ptrs+cold_segment_dir+cold_segments",
            created_at,
        ),
        module_version(PRESSURE_EVENTS_MODULE_ID, 1, "hot_events", created_at),
        module_version(
            ARTIFACT_DEPENDENTS_MODULE_ID,
            3,
            "hot_ptrs+cold_segment_dir+cold_segments",
            created_at,
        ),
    ]
}

pub fn record_current_projection_modules_v1(meta: &mut ProjectionsMetaV1) {
    let current = current_projection_module_versions_at_v1(&meta.created_at);

    for existing in &mut meta.projection_module_registry {
        if current.iter().any(|module| module.module_id == existing.module_id) {
            let still_current = current.iter().any(|module| same_module_identity(module, existing));
            if still_current {
                existing.status = ProjectionModuleStatusV1::Active;
            } else if matches!(existing.status, ProjectionModuleStatusV1::Active) {
                existing.status = ProjectionModuleStatusV1::RetainedForReplay;
            }
        }
    }

    for module in current {
        if !meta
            .projection_module_registry
            .iter()
            .any(|existing| same_module_identity(existing, &module))
        {
            meta.projection_module_registry.push(module);
        }
    }
    meta.projection_module_registry.sort_by(|a, b| {
        (
            a.module_id.as_str(),
            a.module_version.as_str(),
            a.code_hash.as_str(),
            a.config_hash.as_str(),
        )
            .cmp(&(
                b.module_id.as_str(),
                b.module_version.as_str(),
                b.code_hash.as_str(),
                b.config_hash.as_str(),
            ))
    });

    let find = |module_id: &str, registry: &[ProjectionModuleVersionV1]| {
        registry
            .iter()
            .find(|module| module.module_id == module_id && matches!(module.status, ProjectionModuleStatusV1::Active))
            .map(ProjectionModuleVersionV1::ref_v1)
    };

    meta.artifact_living_state.module = find(ARTIFACT_LIVING_STATE_MODULE_ID, &meta.projection_module_registry);
    meta.artifact_relations.module = find(ARTIFACT_RELATIONS_MODULE_ID, &meta.projection_module_registry);
    meta.pressure_events.module = find(PRESSURE_EVENTS_MODULE_ID, &meta.projection_module_registry);
    meta.artifact_dependents.module = find(ARTIFACT_DEPENDENTS_MODULE_ID, &meta.projection_module_registry);
}

fn module_version(module_id: &str, schema_version: u32, config: &str, created_at: &str) -> ProjectionModuleVersionV1 {
    let module_version = format!("{MODULE_VERSION}+schema{schema_version}");
    let code_hash = hash_hex(&format!(
        "corecrux-projections:{MODULE_VERSION}:{module_id}:schema:{schema_version}:runner_v1:state_v1"
    ));
    let config_hash = hash_hex(&format!(
        "corecrux-projections:{module_id}:schema:{schema_version}:ccxs_v1:codec_none:{config}"
    ));
    ProjectionModuleVersionV1 {
        schema: PROJECTION_MODULE_VERSION_SCHEMA_V1.to_string(),
        module_id: module_id.to_string(),
        module_version,
        code_hash,
        schema_version,
        config_hash,
        created_at: created_at.to_string(),
        install_receipt_id: None,
        status: ProjectionModuleStatusV1::Active,
    }
}

fn hash_hex(input: &str) -> String {
    blake3::hash(input.as_bytes()).to_hex().to_string()
}

fn same_module_identity(a: &ProjectionModuleVersionV1, b: &ProjectionModuleVersionV1) -> bool {
    a.module_id == b.module_id
        && a.module_version == b.module_version
        && a.code_hash == b.code_hash
        && a.config_hash == b.config_hash
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
    let mut f = OpenOptions::new().create(true).truncate(true).write(true).open(&tmp)?;
    f.write_all(&bytes)?;
    f.flush()?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_projection_meta_without_module_registry_still_decodes() {
        let json = r#"{
          "v": 1,
          "commitId": 7,
          "createdAt": "2026-05-07T12:00:00Z",
          "artifactLivingState": {"schemaVersion": 1, "rowCount": 1},
          "artifactRelations": {"schemaVersion": 3, "rowCount": 2},
          "pressureEvents": {"schemaVersion": 1, "rowCount": 3},
          "artifactDependents": {"schemaVersion": 3, "rowCount": 4}
        }"#;

        let meta: ProjectionsMetaV1 = serde_json::from_str(json).expect("decode old meta");

        assert_eq!(meta.commit_id, 7);
        assert!(meta.projection_module_registry.is_empty());
        assert!(meta.artifact_living_state.module.is_none());
    }

    #[test]
    fn recording_current_modules_sets_refs_and_retains_old_active_versions() {
        let mut meta = ProjectionsMetaV1::empty_now();
        meta.created_at = "2026-05-07T12:00:00Z".to_string();
        meta.projection_module_registry.push(ProjectionModuleVersionV1 {
            schema: PROJECTION_MODULE_VERSION_SCHEMA_V1.to_string(),
            module_id: ARTIFACT_RELATIONS_MODULE_ID.to_string(),
            module_version: "0.1.0+schema2".to_string(),
            code_hash: "old_code".to_string(),
            schema_version: 2,
            config_hash: "old_config".to_string(),
            created_at: "2026-05-06T12:00:00Z".to_string(),
            install_receipt_id: None,
            status: ProjectionModuleStatusV1::Active,
        });

        record_current_projection_modules_v1(&mut meta);

        let old = meta
            .projection_module_registry
            .iter()
            .find(|module| module.module_version == "0.1.0+schema2")
            .expect("old module retained");
        assert_eq!(old.status, ProjectionModuleStatusV1::RetainedForReplay);
        assert_eq!(
            meta.artifact_relations
                .module
                .as_ref()
                .expect("active relations module")
                .module_id,
            ARTIFACT_RELATIONS_MODULE_ID
        );
        assert_eq!(
            meta.projection_module_registry
                .iter()
                .filter(|module| matches!(module.status, ProjectionModuleStatusV1::Active))
                .count(),
            4
        );
    }
}
