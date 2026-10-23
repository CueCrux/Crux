// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Atomic rollback to a pinned prior pack build — the last of the M5
//! frontier seams of `crux-daemon-buyer-fit-buildout-2026-07-13`.
//!
//! `proof-carrying-adaptive-packs-2026-07-13` M4 quarantines a regressing
//! pack and **atomically restores the previous pin**, with a receipted
//! explanation and no partial or inconsistent pack state. This module is the
//! restore half.
//!
//! ## Where the pins come from
//!
//! Nowhere new. An install record is one fact under
//! `__extension__::{id}::record`, and every rewrite of it — an install, an
//! uninstall tombstone, a lifecycle move — is a new *version* of that fact.
//! The supersession chain the store already keeps **is** the pin ledger, so
//! [`list_pins`] reads history rather than a parallel structure that could
//! disagree with it. No new on-disk artifact class, no new wiring points,
//! and no way for the ledger to drift from what was actually installed.
//!
//! ## What makes it atomic
//!
//! A rollback is exactly one `put_record` — one `try_store`, one journal
//! entry. There is no window in which half a record is restored, because
//! there is no second write to fail. That is a stronger guarantee than
//! compensating writes wrapped in a transaction, and it is why the restore
//! rewrites the whole prior record rather than patching fields of the
//! current one.
//!
//! ## Idempotency
//!
//! Rolling back twice to the same build is a no-op the second time
//! ([`RollbackOutcome::changed`] is `false` and nothing is written), so an
//! automatic responder that retries cannot pile up versions or re-fire the
//! audit event.

use crate::extension_registry::{
    get_extension, put_record, ExtensionsError, InstalledExtension, EXTENSION_ENTITY_PREFIX, EXTENSION_RECORD_KEY,
};
use crate::pack_lifecycle::PackLifecycleState;
use corecrux_memory::fact_store::FactStore;
use crux_integrations::{append_audit_event, IntegrationAuditEvent, TrustTier, AUDIT_EXTENSION_ROLLBACK};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// One restorable point in a pack's history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackPin {
    /// The install record's `fact_id` at this point — the unambiguous
    /// rollback target, since a pack can be re-installed at the same
    /// version and even the same bytes more than once.
    pub fact_id: String,
    /// Position in the record's supersession chain, ascending.
    pub record_version: u32,
    pub extension_version: String,
    pub manifest_hash: String,
    pub trust_tier: TrustTier,
    pub lifecycle: PackLifecycleState,
    pub installed_at_unix_ms: u64,
    pub stored_at_unix_ms: i64,
    /// True for the record in force right now.
    pub is_current: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum RollbackError {
    #[error("extension '{0}' not installed")]
    NotFound(String),
    /// A rollback is a response to something going wrong. Without a reason
    /// the audit trail records that a build changed and nothing about why,
    /// which is exactly the question asked afterwards.
    #[error("rollback requires a non-empty reason")]
    ReasonRequired,
    #[error("no prior pin to roll back to for '{0}'")]
    NoPriorPin(String),
    #[error("no pin matches {0}")]
    TargetNotFound(String),
    #[error(transparent)]
    Registry(#[from] ExtensionsError),
}

/// Which pin to restore.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RollbackTarget {
    /// Exact pin, by install-record `fact_id`. The unambiguous form.
    #[serde(default)]
    pub fact_id: Option<String>,
    /// Or the most recent pin carrying this build's `manifest_hash`.
    #[serde(default)]
    pub manifest_hash: Option<String>,
}

/// Everything one rollback needs.
#[derive(Debug, Clone)]
pub struct RollbackInput {
    pub target: RollbackTarget,
    pub reason: String,
    pub actor: Option<String>,
    /// State to restore the pack into. `None` restores the pin's own
    /// recorded state — "put it back how it was", which is what rollback
    /// means. A caller that wants a cautious restore (an automatic
    /// responder that does not yet trust the older build either) passes
    /// [`PackLifecycleState::Staged`] explicitly rather than having that
    /// judgement made for it here.
    pub lifecycle: Option<PackLifecycleState>,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RollbackOutcome {
    /// False when the pack was already at the target build and state, and
    /// nothing was written.
    pub changed: bool,
    pub from: PackPin,
    pub to: PackPin,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    pub at_unix_ms: u64,
}

fn entity_for(extension_id: &str) -> String {
    format!("{EXTENSION_ENTITY_PREFIX}::{extension_id}")
}

fn pin_of(fact: &corecrux_memory::fact_store::Fact, record: &InstalledExtension, is_current: bool) -> PackPin {
    PackPin {
        fact_id: fact.fact_id.clone(),
        record_version: fact.version,
        extension_version: record.manifest.version.clone(),
        manifest_hash: record.manifest_hash.clone(),
        trust_tier: record.trust_tier,
        lifecycle: record.lifecycle,
        installed_at_unix_ms: record.installed_at_unix_ms,
        stored_at_unix_ms: fact.stored_at.timestamp_millis(),
        is_current,
    }
}

/// Every restorable point in a pack's history, oldest first.
///
/// Uninstall tombstones (empty-value versions) are skipped: "restore the
/// state where this pack was uninstalled" is `DELETE`, not a rollback, and
/// offering it as a pin would make an accidental rollback able to remove a
/// pack.
pub fn list_pins(store: &FactStore, extension_id: &str) -> Vec<PackPin> {
    let entity = entity_for(extension_id);
    let history = store.fact_history("default", &entity, EXTENSION_RECORD_KEY);
    let current_fact_id = history
        .iter()
        .rev()
        .find(|fact| !fact.value.is_empty())
        .map(|fact| fact.fact_id.clone());

    history
        .into_iter()
        .filter(|fact| !fact.value.is_empty())
        .filter_map(|fact| {
            let record = serde_json::from_str::<InstalledExtension>(&fact.value).ok()?;
            let is_current = current_fact_id.as_deref() == Some(fact.fact_id.as_str());
            Some(pin_of(fact, &record, is_current))
        })
        .collect()
}

/// Restore a pinned prior build, atomically.
///
/// One `put_record` — one `try_store`, one journal entry — so the restore
/// either happened or did not; there is no half-restored record to repair.
pub fn rollback(
    store: &mut FactStore,
    data_dir: impl AsRef<Path>,
    extension_id: &str,
    input: RollbackInput,
) -> Result<RollbackOutcome, RollbackError> {
    let reason = input.reason.trim();
    if reason.is_empty() {
        return Err(RollbackError::ReasonRequired);
    }
    let current =
        get_extension(store, extension_id).ok_or_else(|| RollbackError::NotFound(extension_id.to_string()))?;

    let pins = list_pins(store, extension_id);
    let current_pin = pins
        .iter()
        .find(|pin| pin.is_current)
        .cloned()
        .ok_or_else(|| RollbackError::NotFound(extension_id.to_string()))?;
    let target_pin = resolve_target(&pins, &current_pin, &input.target, extension_id)?;

    // Read the record back out of the pin's own fact rather than
    // reconstructing it from the pin's summary fields: the pin is a view,
    // and restoring a view would quietly drop anything it does not carry.
    let entity = entity_for(extension_id);
    let restored_json = store
        .fact_history("default", &entity, EXTENSION_RECORD_KEY)
        .into_iter()
        .find(|fact| fact.fact_id == target_pin.fact_id)
        .map(|fact| fact.value.clone())
        .ok_or_else(|| RollbackError::TargetNotFound(target_pin.fact_id.clone()))?;
    let mut restored: InstalledExtension = serde_json::from_str(&restored_json).map_err(ExtensionsError::from)?;
    if let Some(lifecycle) = input.lifecycle {
        restored.lifecycle = lifecycle;
    }

    // Already there: write nothing. An automatic responder that retries
    // must not pile up record versions or re-fire the audit event.
    if restored.manifest_hash == current.manifest_hash && restored.lifecycle == current.lifecycle {
        return Ok(RollbackOutcome {
            changed: false,
            from: current_pin,
            to: target_pin,
            reason: reason.to_string(),
            actor: input.actor,
            at_unix_ms: input.now_unix_ms,
        });
    }

    put_record(store, &restored)?;

    append_audit_event(
        data_dir,
        &IntegrationAuditEvent::extension(
            input.now_unix_ms,
            AUDIT_EXTENSION_ROLLBACK,
            input.actor.as_deref(),
            extension_id,
            Some(&restored.manifest.version),
            "rolled_back",
            serde_json::json!({
                "from_manifest_hash": current_pin.manifest_hash,
                "from_version": current_pin.extension_version,
                "manifest_hash": restored.manifest_hash,
                "to_version": restored.manifest.version,
                "to_fact_id": target_pin.fact_id,
                "lifecycle": restored.lifecycle,
                "reason": reason,
            }),
        ),
    );

    Ok(RollbackOutcome {
        changed: true,
        from: current_pin,
        to: target_pin,
        reason: reason.to_string(),
        actor: input.actor,
        at_unix_ms: input.now_unix_ms,
    })
}

/// Pick the pin to restore: the named one, or — with nothing named — the
/// most recent pin whose build differs from the current one.
///
/// "Differs from the current one" rather than "the previous version in the
/// chain": a lifecycle move writes a new record version without changing
/// the build, so a positional `previous` would roll back to the same bytes
/// and report success while fixing nothing.
fn resolve_target(
    pins: &[PackPin],
    current: &PackPin,
    target: &RollbackTarget,
    extension_id: &str,
) -> Result<PackPin, RollbackError> {
    if let Some(fact_id) = target.fact_id.as_deref() {
        return pins
            .iter()
            .find(|pin| pin.fact_id == fact_id)
            .cloned()
            .ok_or_else(|| RollbackError::TargetNotFound(format!("fact_id '{fact_id}'")));
    }
    if let Some(hash) = target.manifest_hash.as_deref() {
        return pins
            .iter()
            .rev()
            .find(|pin| pin.manifest_hash == hash)
            .cloned()
            .ok_or_else(|| RollbackError::TargetNotFound(format!("manifest_hash '{hash}'")));
    }
    pins.iter()
        .rev()
        .find(|pin| pin.manifest_hash != current.manifest_hash)
        .cloned()
        .ok_or_else(|| RollbackError::NoPriorPin(extension_id.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extension_registry::{delete_extension, install_extension};
    use crate::pack_lifecycle::set_lifecycle;
    use crux_integrations::{
        DataAccess, EntryKind, IntegrationEntry, IntegrationManifest, ManifestHashes, NetworkAccess, SafetyPolicy,
        INTEGRATION_SCHEMA_V1,
    };

    const ID: &str = "ext.example.quote";

    fn manifest(version: &str, summary: &str) -> IntegrationManifest {
        IntegrationManifest {
            schema: INTEGRATION_SCHEMA_V1.to_string(),
            id: ID.to_string(),
            name: "Quote of the Day".to_string(),
            version: version.to_string(),
            publisher_passport_fpr: "p_alice".to_string(),
            summary: summary.to_string(),
            entry: IntegrationEntry {
                kind: EntryKind::HttpRecipe,
                path: "tools/quote.json".to_string(),
            },
            capabilities: vec!["facts:read".to_string()],
            network: NetworkAccess::default(),
            data_access: DataAccess::default(),
            safety: SafetyPolicy::default(),
            hashes: ManifestHashes::default(),
            signature: None,
            external_tool_endpoint: None,
            tools: Vec::new(),
            wasm_module_path: None,
            wasm_module_url: None,
            wasm_module_sha256: None,
            conformance: None,
        }
    }

    fn input(reason: &str) -> RollbackInput {
        RollbackInput {
            target: RollbackTarget::default(),
            reason: reason.to_string(),
            actor: Some("p_alice".to_string()),
            lifecycle: None,
            now_unix_ms: 17_700_000_000_000,
        }
    }

    /// Install 0.1.0, uninstall, install 0.2.0 — the upgrade path the
    /// registry supports today. The version chain holds both builds.
    fn store_with_two_builds(dir: &Path) -> FactStore {
        let mut store = FactStore::new();
        install_extension(
            &mut store,
            dir,
            manifest("0.1.0", "the old one"),
            None,
            PackLifecycleState::Active,
            1,
            true,
        )
        .expect("install v1");
        delete_extension(&mut store, dir, ID, None, 2).expect("uninstall");
        install_extension(
            &mut store,
            dir,
            manifest("0.2.0", "the new one"),
            None,
            PackLifecycleState::Active,
            3,
            true,
        )
        .expect("install v2");
        store
    }

    /// The pin ledger is the record's own version chain — no parallel
    /// structure, so it cannot disagree with what was installed.
    #[test]
    fn pins_come_from_the_record_version_chain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store_with_two_builds(dir.path());

        let pins = list_pins(&store, ID);
        assert_eq!(pins.len(), 2, "the uninstall tombstone is not a restorable pin");
        assert_eq!(pins[0].extension_version, "0.1.0");
        assert_eq!(pins[1].extension_version, "0.2.0");
        assert!(!pins[0].is_current);
        assert!(pins[1].is_current);
        assert_ne!(pins[0].manifest_hash, pins[1].manifest_hash);
        assert!(pins[0].record_version < pins[1].record_version);
    }

    /// The gate: the previous build comes back, in one write, and it is
    /// what a re-read reports.
    #[test]
    fn rollback_restores_the_previous_build_atomically() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = store_with_two_builds(dir.path());
        let before = get_extension(&store, ID).expect("current");
        assert_eq!(before.manifest.version, "0.2.0");
        let versions_before = store
            .fact_history("default", &entity_for(ID), EXTENSION_RECORD_KEY)
            .len();

        let outcome = rollback(&mut store, dir.path(), ID, input("cost blowup on 0.2.0")).expect("rollback");
        assert!(outcome.changed);
        assert_eq!(outcome.from.extension_version, "0.2.0");
        assert_eq!(outcome.to.extension_version, "0.1.0");

        let after = get_extension(&store, ID).expect("restored");
        assert_eq!(after.manifest.version, "0.1.0");
        assert_eq!(after.manifest.summary, "the old one", "the whole record came back");
        assert_eq!(after.manifest_hash, outcome.to.manifest_hash);
        assert_eq!(
            store
                .fact_history("default", &entity_for(ID), EXTENSION_RECORD_KEY)
                .len(),
            versions_before + 1,
            "exactly one write — there is no window for a half-applied rollback"
        );

        let audit = crux_integrations::read_audit_tail(dir.path(), 50).expect("audit");
        let event = audit.last().expect("event");
        assert_eq!(event.action, AUDIT_EXTENSION_ROLLBACK);
        let detail = event.detail.as_ref().expect("detail");
        assert_eq!(detail.get("from_version"), Some(&serde_json::json!("0.2.0")));
        assert_eq!(detail.get("to_version"), Some(&serde_json::json!("0.1.0")));
        assert_eq!(
            detail.get("reason"),
            Some(&serde_json::json!("cost blowup on 0.2.0")),
            "the audit trail has to answer why, not just what"
        );
    }

    /// An automatic responder retries. A second rollback to the same build
    /// must write nothing rather than pile up versions.
    #[test]
    fn rollback_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = store_with_two_builds(dir.path());
        rollback(&mut store, dir.path(), ID, input("regression")).expect("first");
        let versions = store
            .fact_history("default", &entity_for(ID), EXTENSION_RECORD_KEY)
            .len();
        let audit_len = crux_integrations::read_audit_tail(dir.path(), 100)
            .expect("audit")
            .len();

        let target = list_pins(&store, ID)
            .into_iter()
            .find(|pin| pin.extension_version == "0.1.0" && pin.is_current)
            .expect("0.1.0 is current now");
        let repeat = rollback(
            &mut store,
            dir.path(),
            ID,
            RollbackInput {
                target: RollbackTarget {
                    fact_id: Some(target.fact_id.clone()),
                    manifest_hash: None,
                },
                ..input("regression")
            },
        )
        .expect("second");

        assert!(!repeat.changed);
        assert_eq!(
            store
                .fact_history("default", &entity_for(ID), EXTENSION_RECORD_KEY)
                .len(),
            versions,
            "a no-op rollback must not write a record version"
        );
        assert_eq!(
            crux_integrations::read_audit_tail(dir.path(), 100)
                .expect("audit")
                .len(),
            audit_len,
            "nor re-fire the audit event"
        );
    }

    /// A lifecycle move writes a record version without changing the build.
    /// A positional "previous version" would roll back to the same bytes
    /// and report success while fixing nothing.
    #[test]
    fn the_default_target_skips_pins_of_the_same_build() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = store_with_two_builds(dir.path());
        set_lifecycle(
            &mut store,
            dir.path(),
            ID,
            PackLifecycleState::Quarantined,
            Some("contradiction rate"),
            None,
            4,
            crate::pack_replay::ActivationGate::Advisory,
        )
        .expect("quarantine");
        assert_eq!(
            list_pins(&store, ID).len(),
            3,
            "the quarantine is its own record version"
        );

        let outcome = rollback(&mut store, dir.path(), ID, input("regression")).expect("rollback");
        assert_eq!(
            outcome.to.extension_version, "0.1.0",
            "rolling back must reach a different build, not the same one in another state"
        );
        assert_eq!(get_extension(&store, ID).expect("restored").manifest.version, "0.1.0");
    }

    /// Restore means put it back how it was — including the state it was
    /// in — unless the caller says otherwise.
    #[test]
    fn the_pins_own_state_is_restored_unless_overridden() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = FactStore::new();
        install_extension(
            &mut store,
            dir.path(),
            manifest("0.1.0", "the old one"),
            None,
            PackLifecycleState::Active,
            1,
            true,
        )
        .expect("install v1");
        delete_extension(&mut store, dir.path(), ID, None, 2).expect("uninstall");
        install_extension(
            &mut store,
            dir.path(),
            manifest("0.2.0", "the new one"),
            None,
            PackLifecycleState::Active,
            3,
            true,
        )
        .expect("install v2");

        rollback(&mut store, dir.path(), ID, input("regression")).expect("rollback");
        assert_eq!(
            get_extension(&store, ID).expect("restored").lifecycle,
            PackLifecycleState::Active,
            "the pin was live, so the restore is live"
        );

        // Forward again, then roll back cautiously.
        delete_extension(&mut store, dir.path(), ID, None, 5).expect("uninstall");
        install_extension(
            &mut store,
            dir.path(),
            manifest("0.3.0", "the newest one"),
            None,
            PackLifecycleState::Active,
            6,
            true,
        )
        .expect("install v3");
        rollback(
            &mut store,
            dir.path(),
            ID,
            RollbackInput {
                lifecycle: Some(PackLifecycleState::Staged),
                ..input("regression, and I do not trust the old one either")
            },
        )
        .expect("cautious rollback");
        assert_eq!(
            get_extension(&store, ID).expect("restored").lifecycle,
            PackLifecycleState::Staged
        );
    }

    /// The restore has to survive a restart, or "rolled back" is a claim
    /// about this process only.
    #[test]
    fn a_rollback_survives_a_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let mut store = FactStore::with_persistence(dir.path()).expect("store");
            install_extension(
                &mut store,
                dir.path(),
                manifest("0.1.0", "the old one"),
                None,
                PackLifecycleState::Active,
                1,
                true,
            )
            .expect("install v1");
            delete_extension(&mut store, dir.path(), ID, None, 2).expect("uninstall");
            install_extension(
                &mut store,
                dir.path(),
                manifest("0.2.0", "the new one"),
                None,
                PackLifecycleState::Active,
                3,
                true,
            )
            .expect("install v2");
            rollback(&mut store, dir.path(), ID, input("regression")).expect("rollback");
        }

        let reopened = FactStore::with_persistence(dir.path()).expect("reopen");
        let record = get_extension(&reopened, ID).expect("record survived the restart");
        assert_eq!(record.manifest.version, "0.1.0");
        assert_eq!(record.manifest.summary, "the old one");
        assert!(list_pins(&reopened, ID).iter().any(|pin| pin.is_current));
    }

    #[test]
    fn a_rollback_without_a_reason_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = store_with_two_builds(dir.path());
        let err = rollback(&mut store, dir.path(), ID, input("   ")).expect_err("blank reason");
        assert!(matches!(err, RollbackError::ReasonRequired));
        assert_eq!(
            get_extension(&store, ID).expect("unchanged").manifest.version,
            "0.2.0",
            "a refused rollback must leave the pack where it was"
        );
    }

    #[test]
    fn a_single_build_has_nothing_to_roll_back_to() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = FactStore::new();
        install_extension(
            &mut store,
            dir.path(),
            manifest("0.1.0", "the only one"),
            None,
            PackLifecycleState::Active,
            1,
            true,
        )
        .expect("install");
        let err = rollback(&mut store, dir.path(), ID, input("regression")).expect_err("no prior pin");
        assert!(matches!(err, RollbackError::NoPriorPin(_)));
    }

    #[test]
    fn an_unknown_target_is_refused_and_changes_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = store_with_two_builds(dir.path());
        let err = rollback(
            &mut store,
            dir.path(),
            ID,
            RollbackInput {
                target: RollbackTarget {
                    fact_id: Some("f_not_a_real_pin".to_string()),
                    manifest_hash: None,
                },
                ..input("regression")
            },
        )
        .expect_err("unknown target");
        assert!(matches!(err, RollbackError::TargetNotFound(_)));
        assert_eq!(get_extension(&store, ID).expect("unchanged").manifest.version, "0.2.0");
    }

    #[test]
    fn a_target_can_be_named_by_manifest_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = store_with_two_builds(dir.path());
        let old = list_pins(&store, ID)
            .into_iter()
            .find(|pin| pin.extension_version == "0.1.0")
            .expect("old pin");

        let outcome = rollback(
            &mut store,
            dir.path(),
            ID,
            RollbackInput {
                target: RollbackTarget {
                    fact_id: None,
                    manifest_hash: Some(old.manifest_hash.clone()),
                },
                ..input("regression")
            },
        )
        .expect("rollback by hash");
        assert!(outcome.changed);
        assert_eq!(outcome.to.manifest_hash, old.manifest_hash);
    }
}
