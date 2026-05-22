// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Passport-category write enforcement.
//!
//! Per ExecPlan crux-tenant-category-model-2026-05-22 M3: a passport with
//! `category=personal` may NOT write to an entity whose effective category is
//! `work` or `public`, and vice versa. The check composes the M1 classifier +
//! M2 override layer to resolve "effective category" per entity.
//!
//! Bypasses (the call resolves to `Ok(())` immediately):
//!   - `TenantCategory::System` entities (`__bootstrap__::*`, `__passport__::*`,
//!     `__session_binding__::*`, `__tenant_metadata__::*`, etc.) — the daemon
//!     writes these for its own bookkeeping under any active passport.
//!   - No `passport_id` supplied. The check is per-passport; without an
//!     identifiable passport there is nothing per-passport to gate. This
//!     matches the existing `raw_admin_write` convention in
//!     `crates/corecruxd/src/http/facts.rs` (HTTP admin path) and covers
//!     the console-bridge JWT minted in
//!     ExecPlan crux-console-data-plane-bridge-shipped-2026-05-21: Caddy
//!     injects the bridge bearer token but no `x-corecrux-passport-id`
//!     header, so passport_id is None and the write is allowed under whatever
//!     scope the caller already satisfied (admin:write or facts:write).
//!
//! Legacy passports (no `category` field, or a passport_id that doesn't resolve
//! to a `PassportRecord`) are denied per the operator decision recorded in the
//! ExecPlan Decision Log: re-mint with explicit category before retrying. Prod
//! snapshot at M0 showed zero legacy passports, so this is future-proofing.

use corecrux_memory::fact_store::FactStore;

use crate::tenant_category::{classify_tenant, TenantCategory};

#[derive(Debug, thiserror::Error)]
pub enum CategoryEnforcementError {
    #[error(
        "passport '{0}' pre-dates the category field (or is unknown); re-mint with explicit category before writing"
    )]
    LegacyOrMissingPassport(String),
    #[error("passport category '{passport_cat}' cannot write to entity in category '{entity_cat}'")]
    CategoryMismatch { passport_cat: String, entity_cat: String },
}

/// Resolve an entity_id's effective category (system → override → prefix → default).
pub fn effective_category(store: &FactStore, entity_id: &str) -> TenantCategory {
    let prefix = extract_tenant_prefix(entity_id);
    let override_ = crate::tenant_metadata::get_tenant_category_override(store, prefix);
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

/// Check that a writer (identified by an optional passport_id) is permitted to
/// mutate `entity_id` under the M3 category-exclusivity rules.
///
/// Returns `Ok(())` when the write is allowed. Errors carry a human-readable
/// hint suitable for direct surfacing in a 403 problem detail.
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

    // 2) No passport identity supplied: nothing per-passport to gate. The
    //    caller has already passed `require_fact_write_ctx` (facts:write or
    //    admin:write), so route-level access control is satisfied; per-passport
    //    category exclusivity simply doesn't apply when there is no passport.
    let Some(pid) = passport_id else {
        return Ok(());
    };

    let passport = crate::passports::get_passport(store, pid)
        .ok_or_else(|| CategoryEnforcementError::LegacyOrMissingPassport(pid.to_string()))?;

    if passport.category.trim().is_empty() {
        return Err(CategoryEnforcementError::LegacyOrMissingPassport(pid.to_string()));
    }

    if passport.category != entity_cat.as_str() {
        return Err(CategoryEnforcementError::CategoryMismatch {
            passport_cat: passport.category,
            entity_cat: entity_cat.as_str().to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passports;
    use crate::tenant_category::TenantCategory;
    use crate::tenant_metadata::set_tenant_category_override;

    fn fresh_store_with_default_passports() -> (FactStore, std::path::PathBuf) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!("corecruxd-cat-enforce-{nanos}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let mut store = FactStore::new();
        passports::seed_defaults_if_missing(&dir, &mut store, 1).expect("seed defaults");
        (store, dir)
    }

    #[test]
    fn extract_tenant_prefix_basic() {
        assert_eq!(extract_tenant_prefix("execplan::foo"), "execplan");
        assert_eq!(extract_tenant_prefix("__bootstrap__::x"), "__bootstrap__");
        assert_eq!(extract_tenant_prefix("noprefix"), "noprefix");
        assert_eq!(extract_tenant_prefix(""), "");
    }

    #[test]
    fn effective_category_uses_override_when_set() {
        let (mut store, _dir) = fresh_store_with_default_passports();
        // Untagged tenant defaults to Work.
        assert_eq!(effective_category(&store, "execplan::foo"), TenantCategory::Work);
        // Override to Personal.
        set_tenant_category_override(&mut store, "execplan", TenantCategory::Personal).unwrap();
        assert_eq!(effective_category(&store, "execplan::foo"), TenantCategory::Personal);
    }

    #[test]
    fn effective_category_system_wins_over_override() {
        let (store, _dir) = fresh_store_with_default_passports();
        assert_eq!(effective_category(&store, "__bootstrap__::foo"), TenantCategory::System);
    }

    #[test]
    fn check_personal_passport_writes_personal_entity_ok() {
        let (store, _dir) = fresh_store_with_default_passports();
        let result = check_passport_can_write_entity(&store, Some("personal-default"), "personal::notes::status");
        assert!(result.is_ok(), "personal-default writing personal:: ok");
    }

    #[test]
    fn check_personal_passport_writes_work_entity_blocked() {
        let (store, _dir) = fresh_store_with_default_passports();
        let result = check_passport_can_write_entity(&store, Some("personal-default"), "work::team::status");
        match result {
            Err(CategoryEnforcementError::CategoryMismatch {
                passport_cat,
                entity_cat,
            }) => {
                assert_eq!(passport_cat, "personal");
                assert_eq!(entity_cat, "work");
            }
            other => panic!("expected CategoryMismatch, got {other:?}"),
        }
    }

    #[test]
    fn check_personal_passport_blocked_on_untagged_post_flip() {
        // Default-to-Work means an untagged entity is "work"; a personal
        // passport must NOT be able to write it.
        let (store, _dir) = fresh_store_with_default_passports();
        let result = check_passport_can_write_entity(&store, Some("personal-default"), "execplan::foo");
        assert!(matches!(result, Err(CategoryEnforcementError::CategoryMismatch { .. })));
    }

    #[test]
    fn check_work_passport_writes_untagged_ok_post_flip() {
        let (store, _dir) = fresh_store_with_default_passports();
        let result = check_passport_can_write_entity(&store, Some("work-default"), "execplan::foo");
        assert!(result.is_ok());
    }

    #[test]
    fn check_system_entity_exempt_from_personal_passport() {
        let (store, _dir) = fresh_store_with_default_passports();
        let result = check_passport_can_write_entity(&store, Some("personal-default"), "__bootstrap__::seed");
        assert!(result.is_ok(), "system entity exempt regardless of passport");
    }

    #[test]
    fn check_no_passport_header_allowed_in_any_category() {
        // Console-bridge envelope + raw HTTP CLI tools: no passport-id header
        // means nothing per-passport to gate; route-level scope (facts:write
        // or admin:write) already passed by the time we get here.
        let (store, _dir) = fresh_store_with_default_passports();
        for entity in ["work::team::x", "personal::x::y", "public::x::y", "execplan::foo"] {
            let result = check_passport_can_write_entity(&store, None, entity);
            assert!(result.is_ok(), "no-passport allowed for {entity}");
        }
    }

    #[test]
    fn check_unknown_passport_rejected_as_legacy() {
        let (store, _dir) = fresh_store_with_default_passports();
        let result = check_passport_can_write_entity(&store, Some("not-a-real-passport"), "work::x");
        assert!(matches!(
            result,
            Err(CategoryEnforcementError::LegacyOrMissingPassport(_))
        ));
    }

    #[test]
    fn check_override_changes_required_passport_category() {
        let (mut store, _dir) = fresh_store_with_default_passports();
        // `myproject` defaults to Work (post-flip). Override it to Personal.
        set_tenant_category_override(&mut store, "myproject", TenantCategory::Personal).unwrap();
        // Now personal-default can write it, work-default cannot.
        let ok = check_passport_can_write_entity(&store, Some("personal-default"), "myproject::status");
        assert!(ok.is_ok());
        let bad = check_passport_can_write_entity(&store, Some("work-default"), "myproject::status");
        assert!(matches!(bad, Err(CategoryEnforcementError::CategoryMismatch { .. })));
    }
}
