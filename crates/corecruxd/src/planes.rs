// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Planes — sub-units inside a project. Mirror PlanCrux's "plane" concept:
//! a project (e.g. `plancrux`) has many planes (`daemon`, `vaultcrux`,
//! `corecrux`, ...) and each plane carries its own members + tenants +
//! layers (Vision, Goals, etc.).
//!
//! Stored as facts using the existing FactStore:
//!
//! - `__plane__::{project_id}::{plane_id}` key=`record` — the plane descriptor.
//! - `__plane__::{project_id}::{plane_id}::passport::{passport_id}` key=`record` — membership.
//! - `__plane__::{project_id}::{plane_id}::tenant::{tenant_id}` key=`record` — assigned tenant.
//! - `__plane_layer__::{project_id}::{plane_id}::{layer}` key=`content` — layer content (Vision/Goals/etc.).
//!
//! Plane id rules mirror project id rules: lowercase, alphanumerics + `-` `_`, max 64 chars.

#![allow(dead_code)] // API constants exported for sibling crates that consume planes via FFI
#![allow(clippy::unnecessary_wraps)] // kept Result<T> for symmetry with sibling fns + future fallibility

use corecrux_memory::fact_store::{FactQuery, FactStore, StoreFact};
use serde::{Deserialize, Serialize};

pub const PLANE_ENTITY_PREFIX: &str = "__plane__";
pub const PLANE_LAYER_PREFIX: &str = "__plane_layer__";
pub const PLANE_RECORD_KEY: &str = "record";

#[derive(Debug, thiserror::Error)]
pub enum PlanesError {
    #[error("invalid plane id '{0}'")]
    InvalidId(String),
    #[error("plane '{0}/{1}' already exists")]
    DuplicateId(String, String),
    #[error("plane '{0}/{1}' not found")]
    NotFound(String, String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlaneRecord {
    pub project_id: String,
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_passport_id: Option<String>,
    pub created_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlaneMember {
    pub passport_id: String,
    pub role: String,
    pub added_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlaneTenant {
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_passport_id: Option<String>,
    pub added_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlaneDetail {
    #[serde(flatten)]
    pub record: PlaneRecord,
    pub members: Vec<PlaneMember>,
    pub tenants: Vec<PlaneTenant>,
}

pub struct CreatePlaneInput {
    pub project_id: String,
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub default_passport_id: Option<String>,
}

pub fn validate_id(id: &str) -> Result<(), PlanesError> {
    if id.is_empty() || id.len() > 64 {
        return Err(PlanesError::InvalidId(id.to_string()));
    }
    let ok = id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if !ok {
        return Err(PlanesError::InvalidId(id.to_string()));
    }
    Ok(())
}

fn record_entity(project_id: &str, plane_id: &str) -> String {
    format!("{PLANE_ENTITY_PREFIX}::{project_id}::{plane_id}")
}

fn member_entity(project_id: &str, plane_id: &str, passport_id: &str) -> String {
    format!("{PLANE_ENTITY_PREFIX}::{project_id}::{plane_id}::passport::{passport_id}")
}

fn tenant_entity(project_id: &str, plane_id: &str, tenant_id: &str) -> String {
    format!("{PLANE_ENTITY_PREFIX}::{project_id}::{plane_id}::tenant::{tenant_id}")
}

pub fn list_planes(store: &FactStore, project_id: &str) -> Vec<PlaneRecord> {
    let prefix = format!("{PLANE_ENTITY_PREFIX}::{project_id}::");
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(prefix.clone()),
        top_k: 1000,
        token_budget: None,
    });
    let latest = crate::fact_helpers::dedup_latest(result.facts);
    let mut out = Vec::new();
    for fact in latest {
        if fact.key != PLANE_RECORD_KEY {
            continue;
        }
        // Only top-level plane records — skip the `::passport::` and `::tenant::` sub-records.
        let suffix = fact.entity.strip_prefix(&prefix).unwrap_or("");
        if suffix.contains("::") {
            continue;
        }
        if let Ok(rec) = serde_json::from_str::<PlaneRecord>(&fact.value) {
            out.push(rec);
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

pub fn get_plane(store: &FactStore, project_id: &str, plane_id: &str) -> Option<PlaneRecord> {
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: Some(record_entity(project_id, plane_id)),
        entity_prefix: None,
        top_k: 4,
        token_budget: None,
    });
    let latest = crate::fact_helpers::dedup_latest(result.facts);
    latest
        .into_iter()
        .find(|f| f.key == PLANE_RECORD_KEY)
        .and_then(|f| serde_json::from_str::<PlaneRecord>(&f.value).ok())
}

pub fn list_members(store: &FactStore, project_id: &str, plane_id: &str) -> Vec<PlaneMember> {
    let prefix = format!("{PLANE_ENTITY_PREFIX}::{project_id}::{plane_id}::passport::");
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(prefix),
        top_k: 200,
        token_budget: None,
    });
    let latest = crate::fact_helpers::dedup_latest(result.facts);
    latest
        .into_iter()
        .filter(|f| f.key == PLANE_RECORD_KEY)
        .filter_map(|f| serde_json::from_str::<PlaneMember>(&f.value).ok())
        .collect()
}

pub fn list_tenants(store: &FactStore, project_id: &str, plane_id: &str) -> Vec<PlaneTenant> {
    let prefix = format!("{PLANE_ENTITY_PREFIX}::{project_id}::{plane_id}::tenant::");
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(prefix),
        top_k: 200,
        token_budget: None,
    });
    let latest = crate::fact_helpers::dedup_latest(result.facts);
    latest
        .into_iter()
        .filter(|f| f.key == PLANE_RECORD_KEY)
        .filter_map(|f| serde_json::from_str::<PlaneTenant>(&f.value).ok())
        .collect()
}

pub fn get_plane_detail(store: &FactStore, project_id: &str, plane_id: &str) -> Option<PlaneDetail> {
    let record = get_plane(store, project_id, plane_id)?;
    let members = list_members(store, project_id, plane_id);
    let tenants = list_tenants(store, project_id, plane_id);
    Some(PlaneDetail {
        record,
        members,
        tenants,
    })
}

pub fn create_plane(
    store: &mut FactStore,
    input: CreatePlaneInput,
    now_unix_ms: u64,
) -> Result<PlaneRecord, PlanesError> {
    validate_id(&input.id)?;
    if get_plane(store, &input.project_id, &input.id).is_some() {
        return Err(PlanesError::DuplicateId(input.project_id.clone(), input.id.clone()));
    }
    let record = PlaneRecord {
        project_id: input.project_id.clone(),
        id: input.id.clone(),
        name: if input.name.trim().is_empty() {
            input.id.clone()
        } else {
            input.name
        },
        description: input.description.filter(|s| !s.trim().is_empty()),
        default_passport_id: input.default_passport_id.filter(|s| !s.trim().is_empty()),
        created_at_unix_ms: now_unix_ms,
    };
    write_plane_record(store, &record)?;
    Ok(record)
}

pub fn delete_plane(store: &mut FactStore, project_id: &str, plane_id: &str) -> Result<(), PlanesError> {
    if get_plane(store, project_id, plane_id).is_none() {
        return Err(PlanesError::NotFound(project_id.to_string(), plane_id.to_string()));
    }
    // Append-only "delete" — write empty value with confidence 0 for the
    // record itself, members, tenants. The fact store keeps history.
    let prefixes = [
        record_entity(project_id, plane_id),
        format!("{PLANE_ENTITY_PREFIX}::{project_id}::{plane_id}::passport::"),
        format!("{PLANE_ENTITY_PREFIX}::{project_id}::{plane_id}::tenant::"),
    ];
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(format!("{PLANE_ENTITY_PREFIX}::{project_id}::{plane_id}")),
        top_k: 1000,
        token_budget: None,
    });
    let latest = crate::fact_helpers::dedup_latest(result.facts);
    for fact in latest {
        if fact.entity == prefixes[0] || fact.entity.starts_with(&prefixes[1]) || fact.entity.starts_with(&prefixes[2])
        {
            let mut sf = StoreFact {
                tenant_hash: "default".to_string(),
                entity: fact.entity,
                key: fact.key,
                value: String::new(),
                source_receipt: None,
                confidence: 0.0,
                private: true,
                horizon_class: None,
                actor: None,
            };
            crate::fact_privacy::enforce_global(&mut sf);
            store.store(sf);
        }
    }
    Ok(())
}

pub fn add_member(
    store: &mut FactStore,
    project_id: &str,
    plane_id: &str,
    passport_id: &str,
    role: &str,
    now_unix_ms: u64,
) -> Result<PlaneMember, PlanesError> {
    if get_plane(store, project_id, plane_id).is_none() {
        return Err(PlanesError::NotFound(project_id.to_string(), plane_id.to_string()));
    }
    let role = if role.trim().is_empty() {
        "contributor".to_string()
    } else {
        role.to_string()
    };
    let member = PlaneMember {
        passport_id: passport_id.to_string(),
        role,
        added_at_unix_ms: now_unix_ms,
    };
    let value = serde_json::to_string(&member)?;
    let mut sf = StoreFact {
        tenant_hash: "default".to_string(),
        entity: member_entity(project_id, plane_id, passport_id),
        key: PLANE_RECORD_KEY.to_string(),
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

pub fn remove_member(
    store: &mut FactStore,
    project_id: &str,
    plane_id: &str,
    passport_id: &str,
) -> Result<(), PlanesError> {
    let mut sf = StoreFact {
        tenant_hash: "default".to_string(),
        entity: member_entity(project_id, plane_id, passport_id),
        key: PLANE_RECORD_KEY.to_string(),
        value: String::new(),
        source_receipt: None,
        confidence: 0.0,
        private: true,
        horizon_class: None,
        actor: None,
    };
    crate::fact_privacy::enforce_global(&mut sf);
    store.store(sf);
    Ok(())
}

pub fn add_tenant(
    store: &mut FactStore,
    project_id: &str,
    plane_id: &str,
    tenant_id: &str,
    default_passport_id: Option<String>,
    now_unix_ms: u64,
) -> Result<PlaneTenant, PlanesError> {
    if get_plane(store, project_id, plane_id).is_none() {
        return Err(PlanesError::NotFound(project_id.to_string(), plane_id.to_string()));
    }
    let t = PlaneTenant {
        tenant_id: tenant_id.to_string(),
        default_passport_id: default_passport_id.filter(|s| !s.trim().is_empty()),
        added_at_unix_ms: now_unix_ms,
    };
    let value = serde_json::to_string(&t)?;
    let mut sf = StoreFact {
        tenant_hash: "default".to_string(),
        entity: tenant_entity(project_id, plane_id, tenant_id),
        key: PLANE_RECORD_KEY.to_string(),
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

pub fn remove_tenant(
    store: &mut FactStore,
    project_id: &str,
    plane_id: &str,
    tenant_id: &str,
) -> Result<(), PlanesError> {
    let mut sf = StoreFact {
        tenant_hash: "default".to_string(),
        entity: tenant_entity(project_id, plane_id, tenant_id),
        key: PLANE_RECORD_KEY.to_string(),
        value: String::new(),
        source_receipt: None,
        confidence: 0.0,
        private: true,
        horizon_class: None,
        actor: None,
    };
    crate::fact_privacy::enforce_global(&mut sf);
    store.store(sf);
    Ok(())
}

fn write_plane_record(store: &mut FactStore, record: &PlaneRecord) -> Result<(), PlanesError> {
    let value = serde_json::to_string(record)?;
    let mut sf = StoreFact {
        tenant_hash: "default".to_string(),
        entity: record_entity(&record.project_id, &record.id),
        key: PLANE_RECORD_KEY.to_string(),
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
    use corecrux_memory::FactStore;

    fn store() -> FactStore {
        FactStore::new()
    }

    fn input(pid: &str, id: &str) -> CreatePlaneInput {
        CreatePlaneInput {
            project_id: pid.to_string(),
            id: id.to_string(),
            name: format!("Plane {id}"),
            description: Some("test".into()),
            default_passport_id: None,
        }
    }

    #[test]
    fn create_then_get_round_trips() {
        let mut s = store();
        let r = create_plane(&mut s, input("plancrux", "daemon"), 1_000).expect("create");
        assert_eq!(r.id, "daemon");
        let g = get_plane(&s, "plancrux", "daemon").expect("get");
        assert_eq!(g.name, "Plane daemon");
        assert_eq!(g.project_id, "plancrux");
    }

    #[test]
    fn duplicate_create_is_rejected() {
        let mut s = store();
        create_plane(&mut s, input("p", "x"), 1).unwrap();
        let err = create_plane(&mut s, input("p", "x"), 2).unwrap_err();
        assert!(matches!(err, PlanesError::DuplicateId(_, _)));
    }

    #[test]
    fn list_returns_only_top_level_records() {
        let mut s = store();
        create_plane(&mut s, input("p", "a"), 1).unwrap();
        create_plane(&mut s, input("p", "b"), 2).unwrap();
        add_member(&mut s, "p", "a", "passport-1", "contributor", 3).unwrap();
        add_tenant(&mut s, "p", "a", "tenant-1", None, 4).unwrap();
        let lst = list_planes(&s, "p");
        assert_eq!(lst.len(), 2, "list should not include sub-records, got {lst:?}");
        let ids: Vec<_> = lst.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b"]);
    }

    #[test]
    fn add_then_list_members() {
        let mut s = store();
        create_plane(&mut s, input("p", "x"), 1).unwrap();
        add_member(&mut s, "p", "x", "passport-1", "owner", 2).unwrap();
        add_member(&mut s, "p", "x", "passport-2", "contributor", 3).unwrap();
        let m = list_members(&s, "p", "x");
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn add_member_to_unknown_plane_errors() {
        let mut s = store();
        let err = add_member(&mut s, "p", "ghost", "passport-1", "owner", 1).unwrap_err();
        assert!(matches!(err, PlanesError::NotFound(_, _)));
    }

    #[test]
    fn invalid_plane_id_rejected() {
        let mut s = store();
        let bad = CreatePlaneInput {
            project_id: "p".into(),
            id: "Bad Id Has Space".into(),
            name: "x".into(),
            description: None,
            default_passport_id: None,
        };
        let err = create_plane(&mut s, bad, 1).unwrap_err();
        assert!(matches!(err, PlanesError::InvalidId(_)));
    }
}
