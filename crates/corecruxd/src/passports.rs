// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Multi-passport store for the open Crux Daemon.
//!
//! Passports are first-class agent identities. Each one gets its own ed25519
//! signing keypair (32-byte seed at `data_dir/passports/{id}.key`, mode 0600 —
//! mirrors the daemon-root passport convention) plus a metadata fact stored
//! under `__passport__::{id}` in the existing `FactStore`. The fact value is
//! JSON; legacy passport tools (crux-mcp `issue_passport`) write a subset of
//! the same shape, so the stores interoperate.
//!
//! The auto-seed function creates three default passports on first boot — one
//! per tenant category (`personal-default`, `work-default`, `public-default`)
//! — so the rest of the system always has a working default to fall back to.

#![allow(clippy::option_option)] // PATCH tri-state semantics: outer Some=present, inner None=clear, inner Some=set

use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use corecrux_memory::fact_store::{FactQuery, FactStore, StoreFact};
use crux_session::LocalPassportKey;
use rand::Rng;
use serde::{Deserialize, Serialize};

pub const PASSPORT_ENTITY_PREFIX: &str = "__passport__";
pub const PASSPORT_RECORD_KEY: &str = "record";
pub const SUPPORTED_CATEGORIES: &[&str] = &["personal", "work", "public"];

const TIER_ELITE_RECEIPTS: u64 = 2000;
const TIER_TRUSTED_RECEIPTS: u64 = 500;
const TIER_ESTABLISHED_RECEIPTS: u64 = 100;
const TIER_BASIC_RECEIPTS: u64 = 10;

#[derive(Debug, thiserror::Error)]
pub enum PassportsError {
    #[error("invalid id '{0}': must be lowercase alphanumeric with - or _")]
    InvalidId(String),
    #[error("invalid category '{0}': must be one of personal, work, public")]
    InvalidCategory(String),
    #[error("passport id '{0}' already exists")]
    DuplicateId(String),
    #[error("passport id '{0}' not found")]
    NotFound(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("session error: {0}")]
    Session(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PassportRecord {
    pub id: String,
    pub principal_id: String,
    pub public_key_hex: String,
    pub category: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sponsor_id: Option<String>,
    #[serde(default = "default_tier")]
    pub reputation_tier: String,
    #[serde(default)]
    pub receipt_count: u64,
    #[serde(default)]
    pub agent_work_gate: bool,
    #[serde(default)]
    pub is_default_for_category: bool,
    pub issued_at_unix_ms: u64,
}

fn default_tier() -> String {
    "unverified".to_string()
}

pub fn resolve_tier(receipt_count: u64) -> &'static str {
    if receipt_count >= TIER_ELITE_RECEIPTS {
        "elite"
    } else if receipt_count >= TIER_TRUSTED_RECEIPTS {
        "trusted"
    } else if receipt_count >= TIER_ESTABLISHED_RECEIPTS {
        "established"
    } else if receipt_count >= TIER_BASIC_RECEIPTS {
        "basic"
    } else {
        "unverified"
    }
}

pub fn validate_id(id: &str) -> Result<(), PassportsError> {
    if id.is_empty() || id.len() > 64 {
        return Err(PassportsError::InvalidId(id.to_string()));
    }
    let ok = id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if !ok {
        return Err(PassportsError::InvalidId(id.to_string()));
    }
    Ok(())
}

pub fn validate_category(cat: &str) -> Result<(), PassportsError> {
    if SUPPORTED_CATEGORIES.contains(&cat) {
        Ok(())
    } else {
        Err(PassportsError::InvalidCategory(cat.to_string()))
    }
}

pub struct CreatePassportInput {
    pub id: String,
    pub category: String,
    pub sponsor_id: Option<String>,
    pub agent_work_gate: bool,
    pub is_default_for_category: bool,
}

pub fn list_passports(store: &FactStore, category_filter: Option<&str>) -> Vec<PassportRecord> {
    let result = store.query(&FactQuery {
        query: None,
        entity: None,
        entity_prefix: Some(format!("{PASSPORT_ENTITY_PREFIX}::")),
        top_k: 1000,
        token_budget: None,
    });
    let mut out = Vec::new();
    for fact in crate::fact_helpers::dedup_latest(result.facts) {
        if fact.key != PASSPORT_RECORD_KEY {
            continue;
        }
        if let Ok(rec) = serde_json::from_str::<PassportRecord>(&fact.value) {
            if category_filter.is_none_or(|c| rec.category == c) {
                out.push(rec);
            }
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

pub fn get_passport(store: &FactStore, id: &str) -> Option<PassportRecord> {
    list_passports(store, None).into_iter().find(|p| p.id == id)
}

pub fn create_passport(
    data_dir: &Path,
    store: &mut FactStore,
    input: CreatePassportInput,
    now_unix_ms: u64,
) -> Result<PassportRecord, PassportsError> {
    validate_id(&input.id)?;
    validate_category(&input.category)?;
    if get_passport(store, &input.id).is_some() {
        return Err(PassportsError::DuplicateId(input.id));
    }
    let key = generate_keypair_for_passport(data_dir, &input.id)?;
    let record = PassportRecord {
        id: input.id.clone(),
        principal_id: key.passport_fpr().to_string(),
        public_key_hex: key.public_key_hex().to_string(),
        category: input.category,
        sponsor_id: input.sponsor_id,
        reputation_tier: default_tier(),
        receipt_count: 0,
        agent_work_gate: input.agent_work_gate,
        is_default_for_category: input.is_default_for_category,
        issued_at_unix_ms: now_unix_ms,
    };
    if record.is_default_for_category {
        clear_default_for_category(store, &record.category, &record.id);
    }
    write_record(store, &record)?;
    Ok(record)
}

pub struct UpdatePassportInput {
    pub agent_work_gate: Option<bool>,
    pub is_default_for_category: Option<bool>,
    pub sponsor_id: Option<Option<String>>, // outer Some = "user supplied"; inner None clears.
    pub reputation_tier: Option<String>,
    pub receipt_count: Option<u64>,
}

pub fn update_passport(
    store: &mut FactStore,
    id: &str,
    input: UpdatePassportInput,
) -> Result<PassportRecord, PassportsError> {
    let mut record = get_passport(store, id).ok_or_else(|| PassportsError::NotFound(id.to_string()))?;
    if let Some(g) = input.agent_work_gate {
        record.agent_work_gate = g;
    }
    if let Some(d) = input.is_default_for_category {
        if d {
            clear_default_for_category(store, &record.category, &record.id);
        }
        record.is_default_for_category = d;
    }
    if let Some(s) = input.sponsor_id {
        record.sponsor_id = s;
    }
    if let Some(t) = input.reputation_tier {
        record.reputation_tier = t;
    }
    if let Some(c) = input.receipt_count {
        record.receipt_count = c;
        record.reputation_tier = resolve_tier(c).to_string();
    }
    write_record(store, &record)?;
    Ok(record)
}

pub fn delete_passport(store: &mut FactStore, id: &str) -> Result<(), PassportsError> {
    let record = get_passport(store, id).ok_or_else(|| PassportsError::NotFound(id.to_string()))?;
    let entity = format!("{PASSPORT_ENTITY_PREFIX}::{}", record.id);
    let result = store.query(&FactQuery {
        query: None,
        entity: Some(entity),
        entity_prefix: None,
        top_k: 10,
        token_budget: None,
    });
    for fact in result.facts {
        if fact.key == PASSPORT_RECORD_KEY {
            store.delete(&fact.fact_id);
        }
    }
    Ok(())
}

/// Auto-seed the three default passports if no passport with that id already
/// exists. Idempotent — safe to call on every boot.
pub fn seed_defaults_if_missing(
    data_dir: &Path,
    store: &mut FactStore,
    now_unix_ms: u64,
) -> Result<usize, PassportsError> {
    let existing: std::collections::BTreeSet<String> = list_passports(store, None).into_iter().map(|p| p.id).collect();
    let mut created = 0usize;
    for category in SUPPORTED_CATEGORIES {
        let id = format!("{category}-default");
        if existing.contains(&id) {
            continue;
        }
        create_passport(
            data_dir,
            store,
            CreatePassportInput {
                id,
                category: (*category).to_string(),
                sponsor_id: None,
                agent_work_gate: false,
                is_default_for_category: true,
            },
            now_unix_ms,
        )?;
        created += 1;
    }
    Ok(created)
}

#[allow(dead_code)] // wired by M2 (per-session passport binding)
pub fn default_for_category(store: &FactStore, category: &str) -> Option<PassportRecord> {
    list_passports(store, Some(category))
        .into_iter()
        .find(|p| p.is_default_for_category)
        .or_else(|| list_passports(store, Some(category)).into_iter().next())
}

fn clear_default_for_category(store: &mut FactStore, category: &str, except_id: &str) {
    let to_clear: Vec<PassportRecord> = list_passports(store, Some(category))
        .into_iter()
        .filter(|p| p.is_default_for_category && p.id != except_id)
        .collect();
    for mut rec in to_clear {
        rec.is_default_for_category = false;
        let _ = write_record(store, &rec);
    }
}

fn write_record(store: &mut FactStore, record: &PassportRecord) -> Result<(), PassportsError> {
    let value = serde_json::to_string(record)?;
    let mut sf = StoreFact {
        entity: format!("{PASSPORT_ENTITY_PREFIX}::{}", record.id),
        key: PASSPORT_RECORD_KEY.to_string(),
        value,
        source_receipt: None,
        confidence: 1.0,
        private: false,
    };
    crate::fact_privacy::enforce_global(&mut sf);
    store.store(sf);
    Ok(())
}

fn generate_keypair_for_passport(data_dir: &Path, id: &str) -> Result<LocalPassportKey, PassportsError> {
    let path = passport_seed_path(data_dir, id);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if !path.exists() {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let hex_seed = hex::encode(seed);
        fs::write(&path, hex_seed)?;
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&path, perms)?;
        }
    }
    LocalPassportKey::from_path(&path).map_err(|e| PassportsError::Session(e.to_string()))
}

fn passport_seed_path(data_dir: &Path, id: &str) -> PathBuf {
    data_dir.join("passports").join(format!("{id}.key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!("corecruxd-passports-{name}-{nanos}"));
        fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn validate_id_accepts_alphanumeric_dashes_underscores() {
        assert!(validate_id("personal-default").is_ok());
        assert!(validate_id("agent_v1").is_ok());
        assert!(validate_id("a1b2c3").is_ok());
        assert!(validate_id("Bad").is_err());
        assert!(validate_id("with space").is_err());
        assert!(validate_id("").is_err());
    }

    #[test]
    fn create_writes_record_and_seed_file() {
        let dir = temp_dir("create");
        let mut store = FactStore::new();
        let rec = create_passport(
            &dir,
            &mut store,
            CreatePassportInput {
                id: "alice".to_string(),
                category: "personal".to_string(),
                sponsor_id: None,
                agent_work_gate: false,
                is_default_for_category: true,
            },
            1_000,
        )
        .expect("create");
        assert_eq!(rec.id, "alice");
        assert!(rec.principal_id.starts_with("p_"));
        assert!(dir.join("passports").join("alice.key").exists());
        let listed = list_passports(&store, None);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, "alice");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn auto_seed_creates_three_defaults_idempotently() {
        let dir = temp_dir("seed");
        let mut store = FactStore::new();
        let n = seed_defaults_if_missing(&dir, &mut store, 1).expect("seed1");
        assert_eq!(n, 3);
        let n2 = seed_defaults_if_missing(&dir, &mut store, 2).expect("seed2");
        assert_eq!(n2, 0, "idempotent");
        let listed = list_passports(&store, None);
        assert_eq!(listed.len(), 3);
        let categories: std::collections::BTreeSet<_> = listed.iter().map(|p| p.category.as_str()).collect();
        assert_eq!(
            categories,
            ["personal", "work", "public"]
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
        );
        for p in &listed {
            assert!(p.is_default_for_category);
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn setting_default_clears_others_in_same_category() {
        let dir = temp_dir("default-flip");
        let mut store = FactStore::new();
        create_passport(
            &dir,
            &mut store,
            CreatePassportInput {
                id: "personal-a".to_string(),
                category: "personal".to_string(),
                sponsor_id: None,
                agent_work_gate: false,
                is_default_for_category: true,
            },
            1,
        )
        .expect("a");
        create_passport(
            &dir,
            &mut store,
            CreatePassportInput {
                id: "personal-b".to_string(),
                category: "personal".to_string(),
                sponsor_id: None,
                agent_work_gate: false,
                is_default_for_category: false,
            },
            2,
        )
        .expect("b");

        update_passport(
            &mut store,
            "personal-b",
            UpdatePassportInput {
                agent_work_gate: None,
                is_default_for_category: Some(true),
                sponsor_id: None,
                reputation_tier: None,
                receipt_count: None,
            },
        )
        .expect("flip");

        let listed = list_passports(&store, Some("personal"));
        let a = listed.iter().find(|p| p.id == "personal-a").expect("a");
        let b = listed.iter().find(|p| p.id == "personal-b").expect("b");
        assert!(!a.is_default_for_category);
        assert!(b.is_default_for_category);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn duplicate_id_rejected() {
        let dir = temp_dir("dup");
        let mut store = FactStore::new();
        let mk = || CreatePassportInput {
            id: "alice".to_string(),
            category: "personal".to_string(),
            sponsor_id: None,
            agent_work_gate: false,
            is_default_for_category: false,
        };
        create_passport(&dir, &mut store, mk(), 1).expect("first");
        let err = create_passport(&dir, &mut store, mk(), 2).expect_err("second should fail");
        assert!(matches!(err, PassportsError::DuplicateId(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_removes_record() {
        let dir = temp_dir("del");
        let mut store = FactStore::new();
        create_passport(
            &dir,
            &mut store,
            CreatePassportInput {
                id: "alice".to_string(),
                category: "personal".to_string(),
                sponsor_id: None,
                agent_work_gate: false,
                is_default_for_category: false,
            },
            1,
        )
        .expect("create");
        delete_passport(&mut store, "alice").expect("delete");
        assert!(get_passport(&store, "alice").is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_for_category_returns_explicit_default_if_present() {
        let dir = temp_dir("def-cat");
        let mut store = FactStore::new();
        create_passport(
            &dir,
            &mut store,
            CreatePassportInput {
                id: "personal-a".to_string(),
                category: "personal".to_string(),
                sponsor_id: None,
                agent_work_gate: false,
                is_default_for_category: false,
            },
            1,
        )
        .expect("a");
        create_passport(
            &dir,
            &mut store,
            CreatePassportInput {
                id: "personal-b".to_string(),
                category: "personal".to_string(),
                sponsor_id: None,
                agent_work_gate: false,
                is_default_for_category: true,
            },
            2,
        )
        .expect("b");
        let def = default_for_category(&store, "personal").expect("default");
        assert_eq!(def.id, "personal-b");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn category_filter_works() {
        let dir = temp_dir("filter");
        let mut store = FactStore::new();
        seed_defaults_if_missing(&dir, &mut store, 1).expect("seed");
        let work_only = list_passports(&store, Some("work"));
        assert_eq!(work_only.len(), 1);
        assert_eq!(work_only[0].id, "work-default");
        let _ = fs::remove_dir_all(&dir);
    }
}
