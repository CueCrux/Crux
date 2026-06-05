// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Passport-category write enforcement (shared by corecruxd's HTTP write paths
//! and crux-mcp's `handle_store_fact`).
//!
//! Per ExecPlan crux-tenant-category-model-2026-05-22 M3 + M3.5: a passport
//! with `category=personal` may NOT write to an entity whose effective category
//! is `work` or `public`, and vice versa.
//!
//! Bypasses (the call resolves to `Ok(())` immediately):
//!   - [`TenantCategory::System`] entities (`__bootstrap__::*`,
//!     `__passport__::*`, `__session_binding__::*`, `__tenant_metadata__::*`,
//!     etc.) — the daemon writes these for its own bookkeeping under any
//!     active passport.
//!   - No `passport_id` supplied. The check is per-passport; without an
//!     identifiable passport there is nothing per-passport to gate. Covers
//!     the console-bridge JWT (Caddy doesn't inject `x-corecrux-passport-id`)
//!     and dev-scope test harnesses.
//!
//! This module lives in `crux-mcp` so both `corecruxd` (HTTP write paths) and
//! `crux-mcp` itself (`handle_store_fact`) can call it. It deliberately does
//! NOT depend on `corecruxd::passports::PassportRecord`; passport metadata is
//! read directly from the FactStore at `__passport__::<id>` key `record`,
//! parsed for the `category` field only. The full passport struct lives in
//! `corecruxd` and is the source of truth — this helper is read-only.

use corecrux_memory::fact_store::FactStore;
use serde::Deserialize;

use crate::tenant_category::{classify_tenant, TenantCategory};

const TENANT_METADATA_PREFIX: &str = "__tenant_metadata__";
const TENANT_METADATA_CATEGORY_KEY: &str = "category";
const PASSPORT_PREFIX: &str = "__passport__";
const PASSPORT_RECORD_KEY: &str = "record";

#[derive(Debug, thiserror::Error)]
pub enum CategoryEnforcementError {
    #[error(
        "passport '{0}' pre-dates the category field (or is unknown); re-mint with explicit category before writing"
    )]
    LegacyOrMissingPassport(String),
    #[error("passport category '{passport_cat}' cannot write to entity in category '{entity_cat}'")]
    CategoryMismatch { passport_cat: String, entity_cat: String },
}

/// Read the override category for `tenant_id`, or `None` if none is set.
/// Tolerant to corrupt / unrecognised values.
pub fn get_tenant_category_override(store: &FactStore, tenant_id: &str) -> Option<TenantCategory> {
    if tenant_id.is_empty() {
        return None;
    }
    let entity = format!("{TENANT_METADATA_PREFIX}::{tenant_id}");
    let mut facts: Vec<&corecrux_memory::fact_store::Fact> = store
        .get_by_entity(&entity)
        .into_iter()
        .filter(|f| f.key == TENANT_METADATA_CATEGORY_KEY)
        .collect();
    facts.sort_by_key(|f| f.version);
    let latest = facts.last()?;
    TenantCategory::parse_user_input(&latest.value).ok()
}

/// Resolve `entity_id`'s effective category (system → override → prefix → default).
pub fn effective_category(store: &FactStore, entity_id: &str) -> TenantCategory {
    let prefix = extract_tenant_prefix(entity_id);
    let override_ = get_tenant_category_override(store, prefix);
    classify_tenant(prefix, override_)
}

/// Returns the substring of `entity_id` before the first `::`, or the whole
/// string if there's no `::`. Mirrors the convention `get_console_tenants`
/// uses to enumerate "tenants" from stored entities.
pub fn extract_tenant_prefix(entity_id: &str) -> &str {
    match entity_id.split_once("::") {
        Some((prefix, _)) => prefix,
        None => entity_id,
    }
}

/// Minimal subset of `corecruxd::passports::PassportRecord` used by the
/// category check. Reads the JSON value of `__passport__::<id>` key `record`
/// and extracts the `category` field. Other fields are ignored.
#[derive(Debug, Deserialize)]
struct PassportCategorySlice {
    #[serde(default)]
    category: String,
}

fn passport_category_for(store: &FactStore, passport_id: &str) -> Option<String> {
    let entity = format!("{PASSPORT_PREFIX}::{passport_id}");
    let facts: Vec<&corecrux_memory::fact_store::Fact> = store
        .get_by_entity(&entity)
        .into_iter()
        .filter(|f| f.key == PASSPORT_RECORD_KEY)
        .collect();
    // Newest first (supersession picks the live version).
    let latest = facts.into_iter().max_by_key(|f| f.version)?;
    let slice: PassportCategorySlice = serde_json::from_str(&latest.value).ok()?;
    Some(slice.category)
}

/// Check that a writer (identified by an optional passport_id) is permitted to
/// mutate `entity_id` under the M3 category-exclusivity rules.
///
/// Returns `Ok(())` when the write is allowed. Errors carry a human-readable
/// hint suitable for direct surfacing in a 403 problem detail or a JSON-RPC
/// error response.
pub fn check_passport_can_write_entity(
    store: &FactStore,
    passport_id: Option<&str>,
    entity_id: &str,
) -> Result<(), CategoryEnforcementError> {
    let entity_cat = effective_category(store, entity_id);

    // 1) System entities: daemon-internal bookkeeping, exempt.
    if matches!(entity_cat, TenantCategory::System) {
        return Ok(());
    }

    // 2) No passport identity supplied: route-level access control already
    //    satisfied; nothing per-passport to gate.
    let Some(pid) = passport_id else {
        return Ok(());
    };

    let category = passport_category_for(store, pid)
        .ok_or_else(|| CategoryEnforcementError::LegacyOrMissingPassport(pid.to_string()))?;

    if category.trim().is_empty() {
        return Err(CategoryEnforcementError::LegacyOrMissingPassport(pid.to_string()));
    }

    if category != entity_cat.as_str() {
        return Err(CategoryEnforcementError::CategoryMismatch {
            passport_cat: category,
            entity_cat: entity_cat.as_str().to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use corecrux_memory::fact_store::StoreFact;

    fn seed_passport(store: &mut FactStore, id: &str, category: &str) {
        let record = serde_json::json!({
            "id": id,
            "principal_id": format!("test::{id}"),
            "public_key_hex": "deadbeef",
            "category": category,
            "issued_at_unix_ms": 1u64,
        });
        store.store(StoreFact {
            entity: format!("__passport__::{id}"),
            key: "record".to_string(),
            value: record.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        });
    }

    fn set_override(store: &mut FactStore, tenant: &str, cat: TenantCategory) {
        store.store(StoreFact {
            entity: format!("__tenant_metadata__::{tenant}"),
            key: "category".to_string(),
            value: cat.as_str().to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        });
    }

    #[test]
    fn extract_tenant_prefix_works() {
        assert_eq!(extract_tenant_prefix("execplan::foo"), "execplan");
        assert_eq!(extract_tenant_prefix("noprefix"), "noprefix");
    }

    #[test]
    fn effective_category_uses_override() {
        let mut store = FactStore::new();
        // Default-to-Work for untagged.
        assert_eq!(effective_category(&store, "execplan::foo"), TenantCategory::Work);
        set_override(&mut store, "execplan", TenantCategory::Personal);
        assert_eq!(effective_category(&store, "execplan::foo"), TenantCategory::Personal);
    }

    #[test]
    fn check_personal_passport_writes_personal_ok() {
        let mut store = FactStore::new();
        seed_passport(&mut store, "p-personal", "personal");
        let r = check_passport_can_write_entity(&store, Some("p-personal"), "personal::a");
        assert!(r.is_ok());
    }

    #[test]
    fn check_personal_passport_writes_work_blocked() {
        let mut store = FactStore::new();
        seed_passport(&mut store, "p-personal", "personal");
        let r = check_passport_can_write_entity(&store, Some("p-personal"), "work::a");
        assert!(matches!(r, Err(CategoryEnforcementError::CategoryMismatch { .. })));
    }

    #[test]
    fn check_personal_passport_blocked_on_untagged_post_flip() {
        // Default is Work; personal cannot write it.
        let mut store = FactStore::new();
        seed_passport(&mut store, "p-personal", "personal");
        let r = check_passport_can_write_entity(&store, Some("p-personal"), "execplan::foo");
        assert!(matches!(r, Err(CategoryEnforcementError::CategoryMismatch { .. })));
    }

    #[test]
    fn check_work_passport_writes_untagged_ok_post_flip() {
        let mut store = FactStore::new();
        seed_passport(&mut store, "p-work", "work");
        let r = check_passport_can_write_entity(&store, Some("p-work"), "execplan::foo");
        assert!(r.is_ok());
    }

    #[test]
    fn check_system_entity_exempt() {
        let mut store = FactStore::new();
        seed_passport(&mut store, "p-personal", "personal");
        let r = check_passport_can_write_entity(&store, Some("p-personal"), "__bootstrap__::seed");
        assert!(r.is_ok());
    }

    #[test]
    fn check_no_passport_bypass() {
        let store = FactStore::new();
        let r = check_passport_can_write_entity(&store, None, "work::a");
        assert!(r.is_ok());
    }

    #[test]
    fn check_unknown_passport_rejected_as_legacy() {
        let store = FactStore::new();
        let r = check_passport_can_write_entity(&store, Some("ghost"), "work::a");
        assert!(matches!(r, Err(CategoryEnforcementError::LegacyOrMissingPassport(_))));
    }

    #[test]
    fn check_empty_category_passport_rejected_as_legacy() {
        let mut store = FactStore::new();
        seed_passport(&mut store, "p-empty", "");
        let r = check_passport_can_write_entity(&store, Some("p-empty"), "work::a");
        assert!(matches!(r, Err(CategoryEnforcementError::LegacyOrMissingPassport(_))));
    }

    #[test]
    fn check_override_changes_required_passport_category() {
        let mut store = FactStore::new();
        seed_passport(&mut store, "p-personal", "personal");
        seed_passport(&mut store, "p-work", "work");
        // Default work; flip to personal.
        set_override(&mut store, "myproject", TenantCategory::Personal);
        let ok = check_passport_can_write_entity(&store, Some("p-personal"), "myproject::x");
        assert!(ok.is_ok());
        let bad = check_passport_can_write_entity(&store, Some("p-work"), "myproject::x");
        assert!(matches!(bad, Err(CategoryEnforcementError::CategoryMismatch { .. })));
    }
}
