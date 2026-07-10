// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
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
/// Key used by MCP-issued passports (`issue_passport` / auto-issue). Unlike the
/// daemon `record` (which carries an explicit `category`), these carry only a
/// `tenant_group` (the collaboration boundary, agent-passport M4). We map that
/// group to the enforceable category so agent-passport writes resolve without a
/// separate daemon mint. See `passport_category_for`.
const PASSPORT_MCP_KEY: &str = "passport";

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
    /// Present on MCP-issued passports (agent-passport M4); absent on daemon
    /// `record`s. Used as the category fallback when no explicit `category`.
    #[serde(default)]
    tenant_group: Option<String>,
}

/// Resolve a passport's enforceable category.
///
/// Precedence: the daemon `record`'s explicit `category` wins. If there is no
/// daemon record (or it carries no category) — the case for MCP-issued
/// passports like `claude-work`/`codex-work` — fall back to the MCP `passport`
/// record's `tenant_group`, mapped through [`TenantCategory::parse_user_input`].
/// A `tenant_group` that isn't a valid category (e.g. a custom group name)
/// yields `None`, so enforcement still fails closed rather than guessing.
fn passport_category_for(store: &FactStore, passport_id: &str) -> Option<String> {
    let entity = format!("{PASSPORT_PREFIX}::{passport_id}");
    let facts: Vec<&corecrux_memory::fact_store::Fact> = store.get_by_entity(&entity);

    // 1) Daemon record with an explicit category (newest version wins).
    if let Some(latest) = facts
        .iter()
        .filter(|f| f.key == PASSPORT_RECORD_KEY)
        .max_by_key(|f| f.version)
    {
        if let Ok(slice) = serde_json::from_str::<PassportCategorySlice>(&latest.value) {
            if !slice.category.trim().is_empty() {
                return Some(slice.category);
            }
        }
    }

    // 2) MCP-issued passport: derive the category from tenant_group.
    let mcp = facts
        .iter()
        .filter(|f| f.key == PASSPORT_MCP_KEY)
        .max_by_key(|f| f.version)?;
    let slice: PassportCategorySlice = serde_json::from_str(&mcp.value).ok()?;
    let group = slice.tenant_group?;
    let category = TenantCategory::parse_user_input(group.trim()).ok()?;
    Some(category.as_str().to_string())
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

    /// Seed an MCP-issued passport (key `passport`) carrying a `tenant_group`
    /// but NO `category` — the shape `issue_passport`/auto-issue writes.
    fn seed_mcp_passport(store: &mut FactStore, id: &str, tenant_group: Option<&str>) {
        let mut record = serde_json::json!({
            "principal_id": id,
            "reputation_tier": "basic",
            "receipt_count": 0u64,
            "issued_at": "2026-06-05T00:00:00Z",
            "passport_hash": "deadbeef",
        });
        if let Some(g) = tenant_group {
            record["tenant_group"] = serde_json::json!(g);
        }
        store.store(StoreFact {
            entity: format!("__passport__::{id}"),
            key: "passport".to_string(),
            value: record.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
    }

    #[test]
    fn mcp_passport_tenant_group_resolves_category_and_enforces() {
        // The agent-passport seam: claude-work is issued MCP-side (key=passport,
        // tenant_group=work, NO daemon record). It must resolve to category=work
        // so a work-entity write passes and a personal-entity write is blocked.
        let mut store = FactStore::new();
        seed_mcp_passport(&mut store, "claude-work", Some("work"));
        assert!(check_passport_can_write_entity(&store, Some("claude-work"), "work::a").is_ok());
        let blocked = check_passport_can_write_entity(&store, Some("claude-work"), "personal::a");
        assert!(matches!(
            blocked,
            Err(CategoryEnforcementError::CategoryMismatch { .. })
        ));
    }

    #[test]
    fn mcp_passport_unknown_tenant_group_fails_closed() {
        // A custom group that isn't a real category must NOT be guessed — the
        // write fails closed (rather than silently allowed).
        let mut store = FactStore::new();
        seed_mcp_passport(&mut store, "p-research", Some("research"));
        let r = check_passport_can_write_entity(&store, Some("p-research"), "work::a");
        assert!(matches!(r, Err(CategoryEnforcementError::LegacyOrMissingPassport(_))));
    }

    #[test]
    fn mcp_passport_missing_tenant_group_fails_closed() {
        let mut store = FactStore::new();
        seed_mcp_passport(&mut store, "p-nogroup", None);
        let r = check_passport_can_write_entity(&store, Some("p-nogroup"), "work::a");
        assert!(matches!(r, Err(CategoryEnforcementError::LegacyOrMissingPassport(_))));
    }

    #[test]
    fn daemon_record_category_takes_precedence_over_mcp_tenant_group() {
        // If both records exist, the explicit daemon `category` wins.
        let mut store = FactStore::new();
        seed_mcp_passport(&mut store, "dual", Some("work"));
        seed_passport(&mut store, "dual", "personal");
        assert!(check_passport_can_write_entity(&store, Some("dual"), "personal::a").is_ok());
        assert!(matches!(
            check_passport_can_write_entity(&store, Some("dual"), "work::a"),
            Err(CategoryEnforcementError::CategoryMismatch { .. })
        ));
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
