// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Per-tenant override storage for [`TenantCategory`].
//!
//! Persists a single fact per tenant:
//!
//! - entity: `__tenant_metadata__::<tenant_id>`  (born private via
//!   `fact_privacy::enforce_global` — see `DEFAULT_PRIVATE_PREFIXES`)
//! - key:    `category`
//! - value:  `personal | work | public`  (string-serialised
//!   [`TenantCategory`]; `system` is rejected at write time)
//!
//! Wired in by ExecPlan crux-tenant-category-model-2026-05-22 M2 to back the
//! `GET/PATCH /v1/console/tenants/:tenant/category` endpoints. The HTTP handler
//! calls [`set_tenant_category_override`] on `PATCH`; the existing
//! `get_console_tenants` handler reads via [`get_tenant_category_override`] so
//! the override participates in `classify_tenant`'s precedence
//! (system → override → prefix → default).
//!
//! Overrides survive across daemon restarts because they live in the regular
//! `FactStore`. Rollback of the daemon binary does NOT delete overrides —
//! pre-M1 code ignores the new entity prefix entirely, which is the cleanest
//! possible rollback shape.

use corecrux_memory::fact_store::{FactStore, StoreFact};
use serde::Deserialize;

use crux_mcp::tenant_category::TenantCategory;

const TENANT_METADATA_PREFIX: &str = "__tenant_metadata__";
const CATEGORY_KEY: &str = "category";

#[derive(Debug, thiserror::Error)]
pub enum TenantMetadataError {
    #[error("tenant_id must not be empty")]
    EmptyTenantId,
    #[error("category 'system' cannot be persisted as an override (it is derived)")]
    SystemNotPersistable,
    #[error("cannot override a system-prefix tenant_id ({0:?})")]
    SystemPrefixTarget(String),
}

fn entity_for(tenant_id: &str) -> String {
    format!("{TENANT_METADATA_PREFIX}::{tenant_id}")
}

/// Read the override category for `tenant_id`, or `None` if no override has
/// been set. Tolerant to corrupt / unrecognised values (returns `None` rather
/// than failing) so a stale fact never blocks classification.
pub fn get_tenant_category_override(store: &FactStore, tenant_id: &str) -> Option<TenantCategory> {
    if tenant_id.is_empty() {
        return None;
    }
    let entity = entity_for(tenant_id);
    let mut facts: Vec<&corecrux_memory::fact_store::Fact> = store
        .get_by_entity(&entity)
        .into_iter()
        .filter(|f| f.key == CATEGORY_KEY)
        .collect();
    // If multiple facts exist (shouldn't, but defensively), pick the most
    // recently created.
    // FactStore upserts via supersession (new fact replaces prior version of
    // the same entity+key); after `store()` only the latest non-deleted fact
    // remains visible via `get_by_entity`. Defensive: pick the highest version
    // in case multiple are visible transiently.
    facts.sort_by_key(|f| f.version);
    let latest = facts.last()?;
    TenantCategory::parse_user_input(&latest.value).ok()
}

/// Persist a category override for `tenant_id`. Rejects:
///   - empty tenant_id
///   - `TenantCategory::System` (system is derived, not settable)
///   - tenant_ids that already match the system-prefix pattern (`__*__::?`)
pub fn set_tenant_category_override(
    store: &mut FactStore,
    tenant_id: &str,
    category: TenantCategory,
) -> Result<(), TenantMetadataError> {
    if tenant_id.is_empty() {
        return Err(TenantMetadataError::EmptyTenantId);
    }
    if matches!(category, TenantCategory::System) {
        return Err(TenantMetadataError::SystemNotPersistable);
    }
    if crux_mcp::tenant_category::is_system_prefix(tenant_id) {
        return Err(TenantMetadataError::SystemPrefixTarget(tenant_id.to_string()));
    }
    let mut sf = StoreFact {
        entity: entity_for(tenant_id),
        key: CATEGORY_KEY.to_string(),
        value: category.as_str().to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false, // enforce_global flips this to true via the reserved prefix
        horizon_class: None,
        actor: None,
    };
    crate::fact_privacy::enforce_global(&mut sf);
    store.store(sf);
    Ok(())
}

/// Delete an override (no-op if not present). Used by future cleanup work;
/// not yet wired to an HTTP route.
#[allow(dead_code)]
pub fn delete_tenant_category_override(store: &mut FactStore, tenant_id: &str) -> bool {
    let entity = entity_for(tenant_id);
    let ids: Vec<String> = store
        .get_by_entity(&entity)
        .into_iter()
        .filter(|f| f.key == CATEGORY_KEY)
        .map(|f| f.fact_id.clone())
        .collect();
    let mut removed = false;
    for id in ids {
        if store.delete(&id) {
            removed = true;
        }
    }
    removed
}

/// Request body for `PATCH /v1/console/tenants/:tenant/category`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct PatchTenantCategoryBody {
    pub category: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_store() -> FactStore {
        FactStore::new()
    }

    #[test]
    fn round_trip_get_returns_none_when_no_override() {
        let store = fresh_store();
        assert!(get_tenant_category_override(&store, "execplan").is_none());
        assert!(get_tenant_category_override(&store, "").is_none());
    }

    #[test]
    fn round_trip_set_then_get() {
        let mut store = fresh_store();
        set_tenant_category_override(&mut store, "execplan", TenantCategory::Work).unwrap();
        assert_eq!(
            get_tenant_category_override(&store, "execplan"),
            Some(TenantCategory::Work)
        );
        assert!(get_tenant_category_override(&store, "other").is_none());
    }

    #[test]
    fn set_overwrites_previous_value() {
        let mut store = fresh_store();
        set_tenant_category_override(&mut store, "execplan", TenantCategory::Work).unwrap();
        set_tenant_category_override(&mut store, "execplan", TenantCategory::Personal).unwrap();
        assert_eq!(
            get_tenant_category_override(&store, "execplan"),
            Some(TenantCategory::Personal)
        );
    }

    #[test]
    fn set_rejects_empty_tenant_id() {
        let mut store = fresh_store();
        assert!(matches!(
            set_tenant_category_override(&mut store, "", TenantCategory::Work),
            Err(TenantMetadataError::EmptyTenantId)
        ));
    }

    #[test]
    fn set_rejects_system_category() {
        let mut store = fresh_store();
        assert!(matches!(
            set_tenant_category_override(&mut store, "execplan", TenantCategory::System),
            Err(TenantMetadataError::SystemNotPersistable)
        ));
    }

    #[test]
    fn set_rejects_system_prefix_target() {
        let mut store = fresh_store();
        assert!(matches!(
            set_tenant_category_override(&mut store, "__bootstrap__", TenantCategory::Work),
            Err(TenantMetadataError::SystemPrefixTarget(_))
        ));
        assert!(matches!(
            set_tenant_category_override(&mut store, "__tenant_metadata__", TenantCategory::Work),
            Err(TenantMetadataError::SystemPrefixTarget(_))
        ));
    }

    #[test]
    fn delete_clears_override() {
        let mut store = fresh_store();
        set_tenant_category_override(&mut store, "execplan", TenantCategory::Work).unwrap();
        assert!(delete_tenant_category_override(&mut store, "execplan"));
        assert!(get_tenant_category_override(&store, "execplan").is_none());
        // second delete is a no-op
        assert!(!delete_tenant_category_override(&mut store, "execplan"));
    }

    #[test]
    fn get_ignores_corrupt_value() {
        let mut store = fresh_store();
        // Bypass set_*'s validation to plant a corrupt override.
        let mut sf = StoreFact {
            entity: entity_for("execplan"),
            key: CATEGORY_KEY.to_string(),
            value: "rubbish".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        };
        crate::fact_privacy::enforce_global(&mut sf);
        store.store(sf);
        // Tolerant: corrupt value yields None (falls back to derived/default).
        assert!(get_tenant_category_override(&store, "execplan").is_none());
    }
}
