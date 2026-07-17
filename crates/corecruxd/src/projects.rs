// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Projects — top-level containers grouping a planning target, allowed
//! passports, and one or more working tenants.
//!
//! Stored as facts using the existing FactStore:
//!
//! - `__project__::{id}` key=`record` — the main project descriptor.
//! - `__project__::{id}::passport::{passport_id}` key=`record` — membership.
//! - `__project__::{id}::tenant::{tenant_id}` key=`record` — assigned tenant.
//!
//! Auto-seeds a `default` project on first boot so the rest of the system
//! always has a project to fall back to.

#![allow(dead_code)] // archived field on ProjectRecord is part of the JSON contract; not all callers read it yet
#![allow(clippy::option_option)] // PATCH tri-state semantics: outer Some=present, inner None=clear, inner Some=set
#![allow(clippy::unnecessary_wraps)] // kept Result<T> for symmetry with sibling fns + future fallibility

use corecrux_memory::fact_store::{FactQuery, FactStore, StoreFact};
use serde::{Deserialize, Serialize};

pub const PROJECT_ENTITY_PREFIX: &str = "__project__";
pub const PROJECT_RECORD_KEY: &str = "record";
pub const DEFAULT_PROJECT_ID: &str = "default";

#[derive(Debug, thiserror::Error)]
pub enum ProjectsError {
    #[error("invalid project id '{0}': must be lowercase alphanumeric with - or _, length 1..=64")]
    InvalidId(String),
    #[error("invalid planning target '{0}': expected 'tenant://<tenant_id>' or 'github://<owner>/<repo>'")]
    InvalidPlanningTarget(String),
    #[error("project '{0}' already exists")]
    DuplicateId(String),
    #[error("project '{0}' not found")]
    NotFound(String),
    /// The named passport doesn't exist in the FactStore at all. Distinct from
    /// `PassportNotAllowed` (which means the passport exists but isn't on
    /// the project's allow list yet).
    #[error("passport '{0}' not found")]
    PassportNotFound(String),
    #[error("passport '{0}' not allowed by project '{1}'")]
    PassportNotAllowed(String, String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectRecord {
    pub id: String,
    pub name: String,
    /// `tenant://{tenant_id}` or `github://{owner}/{repo}`. Null = no planning store yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub planning_target: Option<String>,
    /// The default passport id when sessions for this project don't supply one.
    pub default_passport_id: String,
    pub created_at_unix_ms: u64,
    /// Soft-delete: archived projects stay in the journal but are filtered
    /// out of the default Projects list. Toggle via PATCH.
    #[serde(default)]
    pub archived: bool,
    /// When `true`, this project is auto-selected as the active project on
    /// console load (assuming localStorage doesn't override). Only one
    /// project per daemon should carry this flag — `update_project` clears
    /// it from any other project when one is set.
    #[serde(default)]
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectMember {
    pub passport_id: String,
    pub role: String, // owner / contributor / observer
    pub added_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectTenant {
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_passport_id: Option<String>,
    pub added_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectDetail {
    #[serde(flatten)]
    pub record: ProjectRecord,
    pub members: Vec<ProjectMember>,
    pub tenants: Vec<ProjectTenant>,
}

pub struct CreateProjectInput {
    pub id: String,
    pub name: String,
    pub planning_target: Option<String>,
    pub default_passport_id: String,
    pub working_tenants: Vec<String>,
}

pub fn validate_id(id: &str) -> Result<(), ProjectsError> {
    if id.is_empty() || id.len() > 64 {
        return Err(ProjectsError::InvalidId(id.to_string()));
    }
    let ok = id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if !ok {
        return Err(ProjectsError::InvalidId(id.to_string()));
    }
    Ok(())
}

pub fn validate_planning_target(target: &str) -> Result<(), ProjectsError> {
    if target.starts_with("tenant://") || target.starts_with("github://") {
        Ok(())
    } else {
        Err(ProjectsError::InvalidPlanningTarget(target.to_string()))
    }
}

pub fn list_projects(store: &FactStore) -> Vec<ProjectRecord> {
    // Projects vs. project sub-entities both share the `__project__::` prefix;
    // the project descriptor's entity is exactly `__project__::{id}` (no further
    // `::passport::` or `::tenant::` segments).
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(format!("{PROJECT_ENTITY_PREFIX}::")),
        top_k: 500,
        token_budget: None,
    });
    let mut out = Vec::new();
    for fact in crate::fact_helpers::dedup_latest(result.facts) {
        if fact.key != PROJECT_RECORD_KEY {
            continue;
        }
        // Skip sub-entities (membership / tenant rows) — they have additional `::` segments.
        let suffix = fact
            .entity
            .strip_prefix(&format!("{PROJECT_ENTITY_PREFIX}::"))
            .unwrap_or("");
        if suffix.contains("::") {
            continue;
        }
        if let Ok(rec) = serde_json::from_str::<ProjectRecord>(&fact.value) {
            out.push(rec);
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

pub fn get_project(store: &FactStore, id: &str) -> Option<ProjectRecord> {
    list_projects(store).into_iter().find(|p| p.id == id)
}

pub fn list_members(store: &FactStore, project_id: &str) -> Vec<ProjectMember> {
    let prefix = format!("{PROJECT_ENTITY_PREFIX}::{project_id}::passport::");
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(prefix),
        top_k: 200,
        token_budget: None,
    });
    let mut out = Vec::new();
    for fact in crate::fact_helpers::dedup_latest(result.facts) {
        if fact.key != PROJECT_RECORD_KEY {
            continue;
        }
        if let Ok(m) = serde_json::from_str::<ProjectMember>(&fact.value) {
            out.push(m);
        }
    }
    out.sort_by(|a, b| a.passport_id.cmp(&b.passport_id));
    out
}

pub fn list_tenants(store: &FactStore, project_id: &str) -> Vec<ProjectTenant> {
    let prefix = format!("{PROJECT_ENTITY_PREFIX}::{project_id}::tenant::");
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(prefix),
        top_k: 200,
        token_budget: None,
    });
    let mut out = Vec::new();
    for fact in crate::fact_helpers::dedup_latest(result.facts) {
        if fact.key != PROJECT_RECORD_KEY {
            continue;
        }
        if let Ok(t) = serde_json::from_str::<ProjectTenant>(&fact.value) {
            out.push(t);
        }
    }
    out.sort_by(|a, b| a.tenant_id.cmp(&b.tenant_id));
    out
}

pub fn get_project_detail(store: &FactStore, id: &str) -> Option<ProjectDetail> {
    let record = get_project(store, id)?;
    Some(ProjectDetail {
        record: record.clone(),
        members: list_members(store, id),
        tenants: list_tenants(store, id),
    })
}

pub fn create_project(
    store: &mut FactStore,
    input: CreateProjectInput,
    now_unix_ms: u64,
) -> Result<ProjectRecord, ProjectsError> {
    // Validate everything BEFORE writing anything so a single failure doesn't
    // leave a half-built project on disk. Order matches the cheapest-first
    // validation: id format → planning target → duplicate id → default
    // passport existence. The passport check is the most expensive (queries
    // the store) so it's last.
    validate_id(&input.id)?;
    if let Some(target) = &input.planning_target {
        validate_planning_target(target)?;
    }
    if get_project(store, &input.id).is_some() {
        return Err(ProjectsError::DuplicateId(input.id));
    }
    if crate::passports::get_passport(store, &input.default_passport_id).is_none() {
        return Err(ProjectsError::PassportNotFound(input.default_passport_id));
    }

    let record = ProjectRecord {
        id: input.id.clone(),
        name: if input.name.is_empty() {
            input.id.clone()
        } else {
            input.name
        },
        planning_target: input.planning_target,
        default_passport_id: input.default_passport_id.clone(),
        created_at_unix_ms: now_unix_ms,
        archived: false,
        is_default: false,
    };
    write_record(store, &record)?;
    add_member(store, &record.id, &input.default_passport_id, "owner", now_unix_ms)?;
    for tenant in input.working_tenants {
        add_tenant(
            store,
            &record.id,
            &tenant,
            Some(input.default_passport_id.clone()),
            now_unix_ms,
        )?;
    }
    Ok(record)
}

pub struct UpdateProjectInput {
    pub name: Option<String>,
    pub planning_target: Option<Option<String>>,
    pub default_passport_id: Option<String>,
    /// Soft-delete toggle.
    pub archived: Option<bool>,
    /// When set to `true`, this project becomes the auto-selected default
    /// on console load AND the flag is cleared from any other project that
    /// previously held it (one-default invariant).
    pub is_default: Option<bool>,
}

pub fn update_project(
    store: &mut FactStore,
    id: &str,
    input: UpdateProjectInput,
    _now_unix_ms: u64,
) -> Result<ProjectRecord, ProjectsError> {
    let mut record = get_project(store, id).ok_or_else(|| ProjectsError::NotFound(id.to_string()))?;
    if let Some(name) = input.name {
        if !name.is_empty() {
            record.name = name;
        }
    }
    if let Some(pt) = input.planning_target {
        if let Some(target) = &pt {
            validate_planning_target(target)?;
        }
        record.planning_target = pt;
    }
    if let Some(passport_id) = input.default_passport_id {
        if crate::passports::get_passport(store, &passport_id).is_none() {
            return Err(ProjectsError::PassportNotFound(passport_id));
        }
        record.default_passport_id = passport_id;
    }
    if let Some(archived) = input.archived {
        record.archived = archived;
        // Archiving a default project also clears the default flag — no
        // hidden-default footguns.
        if archived {
            record.is_default = false;
        }
    }
    if let Some(is_default) = input.is_default {
        if is_default {
            // One-default invariant: clear is_default on every other project.
            let others = list_projects(store);
            for other in others {
                if other.id != id && other.is_default {
                    let mut o = other.clone();
                    o.is_default = false;
                    write_record(store, &o)?;
                }
            }
        }
        record.is_default = is_default;
    }
    write_record(store, &record)?;
    Ok(record)
}

pub fn delete_project(store: &mut FactStore, id: &str) -> Result<(), ProjectsError> {
    if get_project(store, id).is_none() {
        return Err(ProjectsError::NotFound(id.to_string()));
    }
    let prefixes = [
        format!("{PROJECT_ENTITY_PREFIX}::{id}"),
        format!("{PROJECT_ENTITY_PREFIX}::{id}::passport::"),
        format!("{PROJECT_ENTITY_PREFIX}::{id}::tenant::"),
    ];
    for prefix in prefixes {
        let result = store.query(&FactQuery {
            min_effective_confidence: None,
            tenant_hash: None,
            query: None,
            entity: None,
            entity_prefix: Some(prefix.clone()),
            top_k: 500,
            token_budget: None,
        });
        for fact in result.facts {
            // For the sub-entity prefixes, delete every match. For the bare
            // id prefix, restrict to the project record itself (sub-entities
            // share the same prefix and are handled via their own pass).
            let is_sub_entity_prefix = prefix.ends_with("::passport::") || prefix.ends_with("::tenant::");
            let is_bare_record =
                fact.entity == format!("{PROJECT_ENTITY_PREFIX}::{id}") && fact.key == PROJECT_RECORD_KEY;
            if is_sub_entity_prefix || is_bare_record {
                store.delete(&fact.fact_id);
            }
        }
    }
    Ok(())
}

pub fn add_member(
    store: &mut FactStore,
    project_id: &str,
    passport_id: &str,
    role: &str,
    now_unix_ms: u64,
) -> Result<ProjectMember, ProjectsError> {
    if get_project(store, project_id).is_none() {
        return Err(ProjectsError::NotFound(project_id.to_string()));
    }
    // PassportNotFound is the right variant when the passport doesn't exist
    // at all; PassportNotAllowed is reserved for "exists but not on the
    // project's allow list" (a future-tense state for richer ACLs).
    if crate::passports::get_passport(store, passport_id).is_none() {
        return Err(ProjectsError::PassportNotFound(passport_id.to_string()));
    }
    let member = ProjectMember {
        passport_id: passport_id.to_string(),
        role: role.to_string(),
        added_at_unix_ms: now_unix_ms,
    };
    let value = serde_json::to_string(&member)?;
    let mut sf = StoreFact {
        tenant_hash: "default".to_string(),
        entity: format!("{PROJECT_ENTITY_PREFIX}::{project_id}::passport::{passport_id}"),
        key: PROJECT_RECORD_KEY.to_string(),
        value,
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    crate::fact_privacy::enforce_global(&mut sf);
    store.store(sf);
    Ok(member)
}

pub fn remove_member(store: &mut FactStore, project_id: &str, passport_id: &str) -> Result<(), ProjectsError> {
    let entity = format!("{PROJECT_ENTITY_PREFIX}::{project_id}::passport::{passport_id}");
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: Some(entity),
        entity_prefix: None,
        top_k: 10,
        token_budget: None,
    });
    for fact in result.facts {
        if fact.key == PROJECT_RECORD_KEY {
            store.delete(&fact.fact_id);
        }
    }
    Ok(())
}

pub fn add_tenant(
    store: &mut FactStore,
    project_id: &str,
    tenant_id: &str,
    default_passport_id: Option<String>,
    now_unix_ms: u64,
) -> Result<ProjectTenant, ProjectsError> {
    if get_project(store, project_id).is_none() {
        return Err(ProjectsError::NotFound(project_id.to_string()));
    }
    let t = ProjectTenant {
        tenant_id: tenant_id.to_string(),
        default_passport_id,
        added_at_unix_ms: now_unix_ms,
    };
    let value = serde_json::to_string(&t)?;
    let mut sf = StoreFact {
        tenant_hash: "default".to_string(),
        entity: format!("{PROJECT_ENTITY_PREFIX}::{project_id}::tenant::{tenant_id}"),
        key: PROJECT_RECORD_KEY.to_string(),
        value,
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    crate::fact_privacy::enforce_global(&mut sf);
    store.store(sf);
    Ok(t)
}

pub fn remove_tenant(store: &mut FactStore, project_id: &str, tenant_id: &str) -> Result<(), ProjectsError> {
    let entity = format!("{PROJECT_ENTITY_PREFIX}::{project_id}::tenant::{tenant_id}");
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: Some(entity),
        entity_prefix: None,
        top_k: 10,
        token_budget: None,
    });
    for fact in result.facts {
        if fact.key == PROJECT_RECORD_KEY {
            store.delete(&fact.fact_id);
        }
    }
    Ok(())
}

/// Auto-seed a `default` project if none exist. Idempotent.
pub fn seed_default_if_missing(store: &mut FactStore, now_unix_ms: u64) -> Result<bool, ProjectsError> {
    if !list_projects(store).is_empty() {
        return Ok(false);
    }
    let personal_default = "personal-default".to_string();
    create_project(
        store,
        CreateProjectInput {
            id: DEFAULT_PROJECT_ID.to_string(),
            name: "Default".to_string(),
            planning_target: None,
            default_passport_id: personal_default,
            working_tenants: vec!["personal".to_string()],
        },
        now_unix_ms,
    )?;
    Ok(true)
}

fn write_record(store: &mut FactStore, record: &ProjectRecord) -> Result<(), ProjectsError> {
    let value = serde_json::to_string(record)?;
    let mut sf = StoreFact {
        tenant_hash: "default".to_string(),
        entity: format!("{PROJECT_ENTITY_PREFIX}::{}", record.id),
        key: PROJECT_RECORD_KEY.to_string(),
        value,
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    crate::fact_privacy::enforce_global(&mut sf);
    store.store(sf);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        // nanos alone collides on VMs with coarse clocks (parallel tests
        // land in the same quantum and share a dir) — salt with pid + a counter.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "corecruxd-projects-{name}-{nanos}-{}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    fn seeded_store() -> (PathBuf, FactStore) {
        let dir = temp_dir("seeded");
        let mut store = FactStore::new();
        crate::passports::seed_defaults_if_missing(&dir, &mut store, 1).expect("seed passports");
        (dir, store)
    }

    #[test]
    fn create_then_list_round_trip() {
        let (dir, mut store) = seeded_store();
        create_project(
            &mut store,
            CreateProjectInput {
                id: "alpha".to_string(),
                name: "Alpha".to_string(),
                planning_target: Some("tenant://alpha-planning".to_string()),
                default_passport_id: "personal-default".to_string(),
                working_tenants: vec!["personal::alpha".to_string()],
            },
            1,
        )
        .expect("create");
        let listed = list_projects(&store);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, "alpha");
        assert_eq!(listed[0].planning_target.as_deref(), Some("tenant://alpha-planning"));
        let detail = get_project_detail(&store, "alpha").expect("detail");
        assert_eq!(detail.members.len(), 1, "owner member auto-added");
        assert_eq!(detail.tenants.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn duplicate_project_rejected() {
        let (dir, mut store) = seeded_store();
        let mk = || CreateProjectInput {
            id: "alpha".to_string(),
            name: "Alpha".to_string(),
            planning_target: None,
            default_passport_id: "personal-default".to_string(),
            working_tenants: vec![],
        };
        create_project(&mut store, mk(), 1).expect("first");
        let err = create_project(&mut store, mk(), 2).expect_err("second");
        assert!(matches!(err, ProjectsError::DuplicateId(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_planning_target_rejected() {
        let (dir, mut store) = seeded_store();
        let err = create_project(
            &mut store,
            CreateProjectInput {
                id: "alpha".to_string(),
                name: "Alpha".to_string(),
                planning_target: Some("https://example.com".to_string()),
                default_passport_id: "personal-default".to_string(),
                working_tenants: vec![],
            },
            1,
        )
        .expect_err("should reject");
        assert!(matches!(err, ProjectsError::InvalidPlanningTarget(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_unknown_passport_rejected() {
        let (dir, mut store) = seeded_store();
        create_project(
            &mut store,
            CreateProjectInput {
                id: "alpha".to_string(),
                name: "Alpha".to_string(),
                planning_target: None,
                default_passport_id: "personal-default".to_string(),
                working_tenants: vec![],
            },
            1,
        )
        .expect("create");
        let err = add_member(&mut store, "alpha", "ghost-passport", "contributor", 2).expect_err("rejected");
        assert!(matches!(err, ProjectsError::PassportNotFound(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_project_is_atomic_when_default_passport_missing() {
        let (dir, mut store) = seeded_store();
        let err = create_project(
            &mut store,
            CreateProjectInput {
                id: "should-not-exist".to_string(),
                name: "Half-built".to_string(),
                planning_target: None,
                default_passport_id: "definitely-not-a-passport".to_string(),
                working_tenants: vec![],
            },
            1,
        )
        .expect_err("must fail when default passport is missing");
        assert!(matches!(err, ProjectsError::PassportNotFound(_)));
        // The project record must NOT have been written. Pre-fix, the partial
        // write would leave it readable via get_project even though the create
        // call returned an error.
        assert!(
            get_project(&store, "should-not-exist").is_none(),
            "project record was written despite failed validation"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_removes_project_and_subentities() {
        let (dir, mut store) = seeded_store();
        create_project(
            &mut store,
            CreateProjectInput {
                id: "alpha".to_string(),
                name: "Alpha".to_string(),
                planning_target: None,
                default_passport_id: "personal-default".to_string(),
                working_tenants: vec!["personal::alpha".to_string()],
            },
            1,
        )
        .expect("create");
        delete_project(&mut store, "alpha").expect("delete");
        assert!(get_project(&store, "alpha").is_none());
        assert!(list_members(&store, "alpha").is_empty());
        assert!(list_tenants(&store, "alpha").is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn auto_seed_creates_default_idempotently() {
        let (dir, mut store) = seeded_store();
        let created = seed_default_if_missing(&mut store, 1).expect("seed");
        assert!(created);
        let again = seed_default_if_missing(&mut store, 2).expect("seed2");
        assert!(!again, "idempotent");
        let listed = list_projects(&store);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, DEFAULT_PROJECT_ID);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn members_and_tenants_filtered_by_project() {
        let (dir, mut store) = seeded_store();
        create_project(
            &mut store,
            CreateProjectInput {
                id: "alpha".to_string(),
                name: "Alpha".to_string(),
                planning_target: None,
                default_passport_id: "personal-default".to_string(),
                working_tenants: vec!["personal::a".to_string()],
            },
            1,
        )
        .expect("a");
        create_project(
            &mut store,
            CreateProjectInput {
                id: "beta".to_string(),
                name: "Beta".to_string(),
                planning_target: None,
                default_passport_id: "work-default".to_string(),
                working_tenants: vec!["work::b".to_string()],
            },
            2,
        )
        .expect("b");
        let alpha_members = list_members(&store, "alpha");
        let beta_members = list_members(&store, "beta");
        assert_eq!(alpha_members.len(), 1);
        assert_eq!(beta_members.len(), 1);
        assert_eq!(alpha_members[0].passport_id, "personal-default");
        assert_eq!(beta_members[0].passport_id, "work-default");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
