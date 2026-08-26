// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Staged activation for packs — the M5 frontier seam of
//! `crux-daemon-buyer-fit-buildout-2026-07-13` that lets a pack **run
//! before it is live**.
//!
//! ## The gap this closes
//!
//! Until now an installed pack was, by construction, an enabled pack: the
//! install record existed, so the dispatcher would run it and commit
//! whatever it wrote. That makes "prove what you do before you touch my
//! memory" unexpressible, which is exactly what
//! `proof-carrying-adaptive-packs-2026-07-13` M1 needs — it replays a
//! pack's declared operations *before* enabling it and blocks the ones
//! whose observed behaviour violates their declared envelope.
//!
//! ## The shape
//!
//! Every install record carries a [`PackLifecycleState`]. The state decides
//! two independent things, and keeping them separate is the whole design:
//!
//! - [`PackLifecycleState::is_dispatchable`] — may this pack run at all?
//!   `Quarantined` is the only "no".
//! - [`PackLifecycleState::commits_writes`] — may its writes reach canonical
//!   memory? `Active` is the only "yes".
//!
//! `Staged` therefore means *runs, observed, commits nothing*. Isolation is
//! achieved by not persisting, rather than by persisting into a shadow
//! namespace: a namespace would be a new on-disk artifact class needing its
//! own four-point wiring, and would leave staged residue behind on every
//! replay. Nothing committed is nothing to clean up, and it is a stronger
//! guarantee to test — "the store is byte-identical after a staged
//! dispatch" is a property, where "the residue went somewhere harmless" is
//! a convention.
//!
//! ## Default-off
//!
//! `Active` is the [`Default`], so every record persisted before this seam
//! deserializes as live and no installed pack changes behaviour. Whether a
//! *new* install lands staged is the operator's call via
//! `CORECRUXD_PACK_STAGING` (default off ⇒ installs stay immediately live,
//! exactly as before) — or, once the operator enforces the pre-enable
//! replay gate, [`initial_install_state`] stages a *declaring* pack no
//! matter how that flag is set, because install is a way of going live too.
//! Transitions are always available regardless of the flag; the flag only
//! picks the initial state.

use crate::extension_registry::{get_extension, put_record, ExtensionsError, InstalledExtension};
use corecrux_memory::fact_store::FactStore;
use crux_integrations::{append_audit_event, IntegrationAuditEvent, IntegrationManifest, AUDIT_EXTENSION_LIFECYCLE};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Operator switch deciding whether a freshly installed pack lands
/// [`PackLifecycleState::Staged`] instead of live. Off by default — turning
/// a behaviour on is the operator's decision, not an upgrade side effect.
pub const PACK_STAGING_ENV: &str = "CORECRUXD_PACK_STAGING";

/// Where a pack sits between "installed" and "trusted with my memory".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackLifecycleState {
    /// Runs, is observed, commits nothing. The state a conformance replay
    /// happens in.
    Staged,
    /// Live: runs and its writes reach canonical memory. The [`Default`],
    /// which is what makes this seam invisible to already-installed packs.
    #[default]
    Active,
    /// Refused at dispatch. Reached either by an operator or (once
    /// `proof-carrying-adaptive-packs` M4 lands) by an automatic regression
    /// response; leaving it requires an explicit reason.
    Quarantined,
}

impl PackLifecycleState {
    /// May the dispatcher run this pack at all? A quarantined pack is
    /// refused before any transport or module is touched.
    pub fn is_dispatchable(self) -> bool {
        !matches!(self, Self::Quarantined)
    }

    /// May this pack's writes reach canonical memory? Only when live —
    /// this single predicate is what both the external-tool and wasm write
    /// paths consult, so there is one answer rather than two.
    pub fn commits_writes(self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Active => "active",
            Self::Quarantined => "quarantined",
        }
    }
}

/// Initial state for a new install, per `CORECRUXD_PACK_STAGING`. Read at
/// the HTTP boundary (mirroring `allow_unsigned_dev`) rather than inside
/// the registry, so the domain function stays a pure function of its
/// arguments and tests never race on process env.
pub fn default_install_state() -> PackLifecycleState {
    let staged = std::env::var(PACK_STAGING_ENV)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    if staged {
        PackLifecycleState::Staged
    } else {
        PackLifecycleState::Active
    }
}

/// The state a freshly installed pack actually starts in.
///
/// Install is the *other* path that takes a pack live, and it does not run
/// through [`set_lifecycle`], so the pre-enable gate
/// (`proof-carrying-adaptive-packs-2026-07-13` M1) has to be applied here
/// too or an enforcing operator gets it on the transition route only. A
/// pack that declares a `pack.conformance.v1` envelope has not earned
/// `active` until a replay of *this build* says so, and at install time no
/// replay can exist yet.
///
/// It is staged rather than refused: the pack has to be installed before
/// `POST /v1/extensions/{id}/replay` has anything to replay. Nothing
/// changes for a pack that declares no envelope (it promised nothing, so
/// there is nothing a replay could contradict) or while the gate is
/// [`crate::pack_replay::ActivationGate::Advisory`], which is the default.
pub fn initial_install_state(
    default_state: PackLifecycleState,
    gate: crate::pack_replay::ActivationGate,
    manifest: &IntegrationManifest,
) -> PackLifecycleState {
    if default_state == PackLifecycleState::Active
        && gate == crate::pack_replay::ActivationGate::Enforced
        && manifest.conformance.is_some()
    {
        return PackLifecycleState::Staged;
    }
    default_state
}

/// What a completed transition records. Returned to the caller and mirrored
/// into the audit tail; `proof-carrying-adaptive-packs` M4 binds its
/// regression evidence to one of these.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecycleTransition {
    pub extension_id: String,
    pub extension_version: String,
    pub from: PackLifecycleState,
    pub to: PackLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    pub at_unix_ms: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    #[error("extension '{0}' not found")]
    NotFound(String),
    /// The pre-enable shadow replay refused this build
    /// (`proof-carrying-adaptive-packs-2026-07-13` M1). Only reachable with
    /// [`crate::pack_replay::ActivationGate::Enforced`]; the pack stays
    /// where it was.
    #[error(transparent)]
    ActivationBlocked(#[from] crate::pack_replay::ActivationBlocked),
    /// Leaving quarantine is the one transition that must not be silent:
    /// it re-admits a pack that something already judged unsafe, so the
    /// justification is part of the record, not an afterthought.
    #[error("leaving quarantine requires a non-empty reason")]
    ReasonRequired,
    #[error(transparent)]
    Registry(#[from] ExtensionsError),
}

/// Move a pack to `to`, persisting the updated install record and auditing
/// the move.
///
/// The record is rewritten as one `store` call, which is a single new
/// version of the same `__extension__::{id}::record` fact — so the previous
/// state is still in the supersession chain (a transition is reversible by
/// construction, not by a compensating write) and there is exactly one
/// commit point that either happens or does not.
///
/// A no-op transition (`from == to`) is still recorded. That is deliberate:
/// a re-affirmation of "yes, this stays quarantined" carries an actor and a
/// reason, and dropping it would lose the operator's decision.
///
/// `gate` decides whether a move *into* [`PackLifecycleState::Active`] has
/// to be licensed by a passing shadow replay
/// (`proof-carrying-adaptive-packs-2026-07-13` M1). It is a parameter
/// rather than an env read for the same reason `initial_state` is: this
/// stays a pure function of its arguments and tests never race on process
/// env. Every path that takes a pack live goes through here, so the check
/// lives in one place rather than at whichever caller remembered it.
#[allow(clippy::too_many_arguments)]
pub fn set_lifecycle(
    store: &mut FactStore,
    data_dir: impl AsRef<Path>,
    extension_id: &str,
    to: PackLifecycleState,
    reason: Option<&str>,
    actor: Option<&str>,
    now_unix_ms: u64,
    gate: crate::pack_replay::ActivationGate,
) -> Result<(InstalledExtension, LifecycleTransition), LifecycleError> {
    let mut record =
        get_extension(store, extension_id).ok_or_else(|| LifecycleError::NotFound(extension_id.to_string()))?;
    let from = record.lifecycle;
    let reason = reason.map(str::trim).filter(|r| !r.is_empty());

    if from == PackLifecycleState::Quarantined && to != PackLifecycleState::Quarantined && reason.is_none() {
        return Err(LifecycleError::ReasonRequired);
    }
    if to == PackLifecycleState::Active && gate == crate::pack_replay::ActivationGate::Enforced {
        crate::pack_replay::check_activation(store, extension_id, &record.manifest, &record.manifest_hash)?;
    }

    record.lifecycle = to;
    put_record(store, &record)?;

    let transition = LifecycleTransition {
        extension_id: extension_id.to_string(),
        extension_version: record.manifest.version.clone(),
        from,
        to,
        reason: reason.map(str::to_string),
        actor: actor.map(str::to_string),
        at_unix_ms: now_unix_ms,
    };
    append_audit_event(
        data_dir,
        &IntegrationAuditEvent::extension(
            now_unix_ms,
            AUDIT_EXTENSION_LIFECYCLE,
            actor,
            extension_id,
            Some(&record.manifest.version),
            to.as_str(),
            serde_json::json!({
                "from": from,
                "to": to,
                "reason": transition.reason,
                "manifest_hash": record.manifest_hash,
            }),
        ),
    );
    Ok((record, transition))
}

/// One write a staged pack *would* have made.
///
/// Deliberately its own wire type rather than the daemon's internal
/// `StoreFact`: this is the record a conformance replay is scored against,
/// so it has to be a contract that can be compared across daemon versions,
/// and `StoreFact` is a deserialize-only request shape that carries
/// tenant-routing fields a replay has no business seeing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObservedFactWrite {
    pub entity: String,
    pub key: String,
    pub value: String,
    pub confidence: f32,
    /// Post-privacy-gate, so a replay sees the same privacy posture the
    /// write would really have landed with.
    pub private: bool,
    /// The pack's [`crate::extension_registry::PackAttribution::actor`]
    /// stamp — the same value a live run would have written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
}

impl ObservedFactWrite {
    pub fn from_store_fact(sf: &corecrux_memory::fact_store::StoreFact) -> Self {
        Self {
            entity: sf.entity.clone(),
            key: sf.key.clone(),
            value: sf.value.clone(),
            confidence: sf.confidence,
            private: sf.private,
            actor: sf.actor.clone(),
        }
    }
}

/// What a completed dispatch's writes are allowed to do.
#[derive(Debug)]
pub enum DispatchWrites {
    /// Live pack — persist these, in dispatch order.
    Commit(Vec<corecrux_memory::fact_store::StoreFact>),
    /// Staged pack — persist nothing; this is what a live run would have
    /// written.
    Observe(Vec<ObservedFactWrite>),
}

/// Decide what becomes of the writes a dispatch produced.
///
/// The one place the commit decision is made for the external-tool path,
/// so "does a staged pack touch memory" is a property of a named function
/// with a test rather than of an `if` in a request handler. The privacy
/// gate runs on both arms before the branch: what a staged run reports has
/// to be exactly what a live run would have persisted, gate included, or
/// the replay is observing something that never happens.
pub fn classify_dispatch_writes(
    lifecycle: PackLifecycleState,
    mut writes: Vec<corecrux_memory::fact_store::StoreFact>,
) -> DispatchWrites {
    for sf in &mut writes {
        crate::fact_privacy::enforce_global(sf);
    }
    if lifecycle.commits_writes() {
        DispatchWrites::Commit(writes)
    } else {
        DispatchWrites::Observe(writes.iter().map(ObservedFactWrite::from_store_fact).collect())
    }
}

/// Envelope the HTTP layer returns for a dispatch that did **not** commit.
///
/// The dispatch outcome is flattened in verbatim so a caller reading a
/// staged run sees the same fields it would see from a live one, plus the
/// three that say what happened to the writes. Making staging an envelope
/// rather than three more optional fields on `DispatchOutcome` keeps the
/// dispatcher's contract about dispatching; whether a write lands is the
/// registry's business, not the transport's.
#[derive(Debug, Clone, Serialize)]
pub struct StagedDispatchEnvelope<T: Serialize> {
    pub lifecycle: PackLifecycleState,
    /// Always `false` here — present so a consumer can branch on one field
    /// without inferring commit semantics from the state name.
    pub committed: bool,
    /// Exactly the writes a live run would have persisted, after the grant
    /// filter and the privacy gate, in dispatch order. This is the raw
    /// material `proof-carrying-adaptive-packs` M1 compares against a
    /// declared envelope.
    pub observed_fact_writes: Vec<ObservedFactWrite>,
    #[serde(flatten)]
    pub outcome: T,
}

impl<T: Serialize> StagedDispatchEnvelope<T> {
    pub fn new(lifecycle: PackLifecycleState, observed_fact_writes: Vec<ObservedFactWrite>, outcome: T) -> Self {
        Self {
            lifecycle,
            committed: false,
            observed_fact_writes,
            outcome,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extension_registry::{install_extension, PackAttribution};
    use crux_integrations::{
        DataAccess, EntryKind, IntegrationEntry, IntegrationManifest, ManifestHashes, NetworkAccess, SafetyPolicy,
        INTEGRATION_SCHEMA_V1,
    };

    fn fixture_manifest(id: &str) -> IntegrationManifest {
        IntegrationManifest {
            schema: INTEGRATION_SCHEMA_V1.to_string(),
            id: id.to_string(),
            name: "Quote of the Day".to_string(),
            version: "0.1.0".to_string(),
            publisher_passport_fpr: "p_alice".to_string(),
            summary: "Returns a quote.".to_string(),
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

    fn install(store: &mut FactStore, dir: &Path, state: PackLifecycleState) -> InstalledExtension {
        install_extension(
            store,
            dir,
            fixture_manifest("ext.example.quote"),
            None,
            state,
            17_700_000_000_000,
            true,
        )
        .expect("install")
    }

    /// Back-compat is the whole reason `Active` is the default: an install
    /// record persisted before this seam existed has no `lifecycle` field,
    /// and must deserialize as live rather than as "not yet enabled".
    #[test]
    fn record_without_a_lifecycle_field_deserializes_active() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = FactStore::new();
        let record = install(&mut store, dir.path(), PackLifecycleState::Active);

        let mut json = serde_json::to_value(&record).expect("serialize");
        json.as_object_mut().expect("object").remove("lifecycle");
        assert!(json.get("lifecycle").is_none(), "field removed for the test");

        let round_tripped: InstalledExtension = serde_json::from_value(json).expect("deserialize legacy record");
        assert_eq!(round_tripped.lifecycle, PackLifecycleState::Active);
    }

    /// The two predicates are independent, and staged is the interesting
    /// corner: it runs *and* commits nothing.
    #[test]
    fn staged_runs_but_never_commits_quarantined_does_neither() {
        assert!(PackLifecycleState::Staged.is_dispatchable());
        assert!(!PackLifecycleState::Staged.commits_writes());
        assert!(PackLifecycleState::Active.is_dispatchable());
        assert!(PackLifecycleState::Active.commits_writes());
        assert!(!PackLifecycleState::Quarantined.is_dispatchable());
        assert!(!PackLifecycleState::Quarantined.commits_writes());
    }

    #[test]
    fn transition_persists_and_audits() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = FactStore::new();
        install(&mut store, dir.path(), PackLifecycleState::Staged);

        let (record, transition) = set_lifecycle(
            &mut store,
            dir.path(),
            "ext.example.quote",
            PackLifecycleState::Active,
            Some("replay clean"),
            Some("agent-claude"),
            17_700_000_000_001,
            crate::pack_replay::ActivationGate::Advisory,
        )
        .expect("activate");

        assert_eq!(record.lifecycle, PackLifecycleState::Active);
        assert_eq!(transition.from, PackLifecycleState::Staged);
        assert_eq!(transition.to, PackLifecycleState::Active);
        assert_eq!(
            get_extension(&store, "ext.example.quote").expect("re-read").lifecycle,
            PackLifecycleState::Active,
            "the state has to survive a re-read, not just the return value"
        );

        let audit = crux_integrations::read_audit_tail(dir.path(), 50).expect("audit");
        let event = audit.last().expect("event");
        assert_eq!(event.action, AUDIT_EXTENSION_LIFECYCLE);
        assert_eq!(event.outcome, "active");
        let detail = event.detail.as_ref().expect("detail");
        assert_eq!(detail.get("from"), Some(&serde_json::json!("staged")));
        assert_eq!(detail.get("reason"), Some(&serde_json::json!("replay clean")));
    }

    /// A transition must not disturb the attribution stamp — the pack build
    /// that wrote a fact is a property of the bytes installed, not of
    /// whether it happens to be live right now.
    #[test]
    fn transition_preserves_attribution() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = FactStore::new();
        let installed = install(&mut store, dir.path(), PackLifecycleState::Active);
        let before = PackAttribution::from_installed(&installed).actor();

        let (record, _) = set_lifecycle(
            &mut store,
            dir.path(),
            "ext.example.quote",
            PackLifecycleState::Quarantined,
            Some("cost blowup"),
            None,
            2,
            crate::pack_replay::ActivationGate::Advisory,
        )
        .expect("quarantine");
        assert_eq!(PackAttribution::from_installed(&record).actor(), before);
    }

    /// Re-admitting something already judged unsafe is the one move that
    /// has to carry a justification.
    #[test]
    fn leaving_quarantine_without_a_reason_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = FactStore::new();
        install(&mut store, dir.path(), PackLifecycleState::Active);
        set_lifecycle(
            &mut store,
            dir.path(),
            "ext.example.quote",
            PackLifecycleState::Quarantined,
            Some("contradiction rate"),
            None,
            2,
            crate::pack_replay::ActivationGate::Advisory,
        )
        .expect("quarantine");

        let err = set_lifecycle(
            &mut store,
            dir.path(),
            "ext.example.quote",
            PackLifecycleState::Active,
            Some("   "),
            None,
            3,
            crate::pack_replay::ActivationGate::Advisory,
        )
        .expect_err("blank reason is no reason");
        assert!(matches!(err, LifecycleError::ReasonRequired));

        assert_eq!(
            get_extension(&store, "ext.example.quote").expect("re-read").lifecycle,
            PackLifecycleState::Quarantined,
            "a refused transition must leave the pack where it was"
        );

        set_lifecycle(
            &mut store,
            dir.path(),
            "ext.example.quote",
            PackLifecycleState::Active,
            Some("operator override: false positive"),
            Some("p_alice"),
            4,
            crate::pack_replay::ActivationGate::Advisory,
        )
        .expect("override with a reason is allowed");
    }

    /// Entering quarantine must never be blocked for want of a reason —
    /// the asymmetry is the safety property.
    #[test]
    fn entering_quarantine_needs_no_reason() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = FactStore::new();
        install(&mut store, dir.path(), PackLifecycleState::Active);
        let (record, _) = set_lifecycle(
            &mut store,
            dir.path(),
            "ext.example.quote",
            PackLifecycleState::Quarantined,
            None,
            None,
            2,
            crate::pack_replay::ActivationGate::Advisory,
        )
        .expect("quarantine without a reason");
        assert_eq!(record.lifecycle, PackLifecycleState::Quarantined);
    }

    fn proposed_write(entity: &str) -> corecrux_memory::fact_store::StoreFact {
        corecrux_memory::fact_store::StoreFact {
            tenant_hash: corecrux_memory::fact_store::default_tenant_hash(),
            entity: entity.to_string(),
            key: "content".to_string(),
            value: "Roses are red".to_string(),
            source_receipt: None,
            confidence: 0.9,
            private: false,
            horizon_class: None,
            actor: Some("pack:ext.example.quote@0.1.0#blake3:deadbeef".to_string()),
        }
    }

    /// The load-bearing property of the whole seam: a staged pack's
    /// dispatch leaves canonical memory exactly as it found it. Asserted
    /// against a real store, both arms, so "commits nothing" is measured
    /// rather than argued.
    #[test]
    fn a_staged_dispatch_leaves_the_store_untouched() {
        let entity = "personal::quotes::today";
        let count = |store: &FactStore| {
            store
                .query(&corecrux_memory::fact_store::FactQuery {
                    min_effective_confidence: None,
                    tenant_hash: None,
                    query: None,
                    entity: Some(entity.to_string()),
                    entity_prefix: None,
                    top_k: 16,
                    token_budget: None,
                })
                .facts
                .len()
        };

        let mut staged_store = FactStore::new();
        let before = count(&staged_store);
        match classify_dispatch_writes(PackLifecycleState::Staged, vec![proposed_write(entity)]) {
            DispatchWrites::Observe(observed) => {
                assert_eq!(observed.len(), 1);
                assert_eq!(observed[0].entity, entity);
                assert_eq!(
                    observed[0].actor.as_deref(),
                    Some("pack:ext.example.quote@0.1.0#blake3:deadbeef"),
                    "the observation carries the same attribution a live write would have"
                );
            }
            DispatchWrites::Commit(_) => panic!("a staged pack must never reach the commit arm"),
        }
        assert_eq!(count(&staged_store), before, "staged dispatch stored something");
        // Nothing to store, but prove the store was usable all along — the
        // emptiness is the pack's doing, not a broken fixture.
        staged_store.store(proposed_write(entity));
        assert_eq!(count(&staged_store), 1);

        let mut live_store = FactStore::new();
        match classify_dispatch_writes(PackLifecycleState::Active, vec![proposed_write(entity)]) {
            DispatchWrites::Commit(writes) => {
                assert_eq!(writes.len(), 1);
                for sf in writes {
                    live_store.store(sf);
                }
            }
            DispatchWrites::Observe(_) => panic!("a live pack must commit"),
        }
        assert_eq!(count(&live_store), 1, "the same input does land when the pack is live");
    }

    /// Quarantine is enforced upstream (the dispatcher never runs), but if
    /// writes ever reach here from a quarantined pack they must not land.
    #[test]
    fn a_quarantined_pack_never_reaches_the_commit_arm() {
        assert!(matches!(
            classify_dispatch_writes(
                PackLifecycleState::Quarantined,
                vec![proposed_write("personal::quotes::today")]
            ),
            DispatchWrites::Observe(_)
        ));
    }

    /// The privacy gate runs before the branch, so an observation reports
    /// the posture the write would really have had.
    #[test]
    fn observed_writes_carry_the_post_gate_privacy_posture() {
        match classify_dispatch_writes(
            PackLifecycleState::Staged,
            vec![proposed_write("__extension__::sneaky")],
        ) {
            DispatchWrites::Observe(observed) => {
                assert!(
                    observed[0].private,
                    "a reserved-prefix write is private when live, so it must read private when staged"
                );
            }
            DispatchWrites::Commit(_) => panic!("staged"),
        }
    }

    /// The pre-enable gate, at the one function every lifecycle move goes
    /// through: with enforcement on, a declaring pack whose shadow replay
    /// was blocked cannot be taken live, and it stays exactly where it was
    /// (`proof-carrying-adaptive-packs-2026-07-13` M1).
    #[test]
    fn an_envelope_violating_pack_cannot_be_taken_live_when_the_gate_is_enforced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = FactStore::new();
        let mut manifest = fixture_manifest("ext.example.quote");
        // A conformance block only means something on a pack that executes,
        // so the declaration validator refuses any other entry kind.
        manifest.entry.kind = crux_integrations::EntryKind::ExternalTool;
        manifest.external_tool_endpoint = Some("https://quote.pack.invalid/tools".to_string());
        manifest.network.allowed_hosts = vec!["quote.pack.invalid".to_string()];
        manifest.tools = vec![crux_integrations::ExternalToolDefinition {
            name: "ext.example.quote.daily".to_string(),
            description: "Returns a quote.".to_string(),
            input_schema: serde_json::json!({}),
            consequence_metadata: None,
            auth_shared_secret_id: None,
        }];
        manifest.conformance = Some(declaring_conformance());
        let installed = install_extension(
            &mut store,
            dir.path(),
            manifest,
            None,
            PackLifecycleState::Staged,
            17_700_000_000_000,
            true,
        )
        .expect("install");

        // No replay on record at all: a declaring pack has proved nothing.
        let err = set_lifecycle(
            &mut store,
            dir.path(),
            "ext.example.quote",
            PackLifecycleState::Active,
            None,
            None,
            1,
            crate::pack_replay::ActivationGate::Enforced,
        )
        .expect_err("an unproved declaring pack must not go live");
        assert!(matches!(err, LifecycleError::ActivationBlocked(_)), "{err}");
        assert_eq!(
            get_extension(&store, "ext.example.quote").expect("re-read").lifecycle,
            PackLifecycleState::Staged,
            "a refused activation must leave the pack staged"
        );

        // Advisory (the shipped default) reports rather than refuses, so no
        // pack changes behaviour until an operator turns the gate on.
        set_lifecycle(
            &mut store,
            dir.path(),
            "ext.example.quote",
            PackLifecycleState::Active,
            None,
            None,
            2,
            crate::pack_replay::ActivationGate::Advisory,
        )
        .expect("advisory must permit");
        assert_eq!(
            PackAttribution::from_installed(&installed).manifest_hash,
            installed.manifest_hash
        );
    }

    /// The other way a pack goes live is by being installed live, and that
    /// path does not run through [`set_lifecycle`]. With enforcement on, a
    /// declaring pack lands staged instead — it cannot have been replayed
    /// yet, so it has not earned `active`
    /// (`proof-carrying-adaptive-packs-2026-07-13` M1).
    #[test]
    fn a_declaring_pack_is_not_installed_live_while_the_gate_is_enforced() {
        let mut declaring = fixture_manifest("ext.example.quote");
        declaring.conformance = Some(declaring_conformance());
        let silent = fixture_manifest("ext.example.legacy");

        assert_eq!(
            initial_install_state(
                PackLifecycleState::Active,
                crate::pack_replay::ActivationGate::Enforced,
                &declaring,
            ),
            PackLifecycleState::Staged,
            "an enforcing operator must not get a live, never-replayed declaring pack"
        );

        // A pack that declared no envelope promised nothing, so there is
        // nothing a replay could contradict and nothing to gate.
        assert_eq!(
            initial_install_state(
                PackLifecycleState::Active,
                crate::pack_replay::ActivationGate::Enforced,
                &silent,
            ),
            PackLifecycleState::Active
        );

        // Advisory is the shipped default: no install changes state.
        assert_eq!(
            initial_install_state(
                PackLifecycleState::Active,
                crate::pack_replay::ActivationGate::Advisory,
                &declaring,
            ),
            PackLifecycleState::Active
        );

        // And `CORECRUXD_PACK_STAGING` still wins where it already applied.
        assert_eq!(
            initial_install_state(
                PackLifecycleState::Staged,
                crate::pack_replay::ActivationGate::Advisory,
                &silent,
            ),
            PackLifecycleState::Staged
        );
    }

    /// The smallest declaration that parses: enough to make the pack a
    /// *declaring* pack, which is what arms the gate.
    fn declaring_conformance() -> crux_integrations::conformance::PackConformance {
        use crux_integrations::conformance::*;
        PackConformance {
            schema: PACK_CONFORMANCE_SCHEMA_V1.to_string(),
            claimed_capabilities: vec!["facts:read".to_string()],
            expected_mutations: ExpectedMutations {
                facts: Vec::new(),
                receipts: Vec::new(),
            },
            replay_corpus: ReplayCorpus {
                corpus_id: "quote-shadow-v1".to_string(),
                path: "replay-corpus.json".to_string(),
                sha256: "0".repeat(64),
                cases: vec![DeclaredCase {
                    case_id: "daily".to_string(),
                    tool_name: "ext.example.quote.daily".to_string(),
                    args: serde_json::json!({}),
                }],
            },
            invariants: vec![InvariantTest {
                id: "egress-pinned".to_string(),
                description: "The pack reaches no host outside network.allowed_hosts.".to_string(),
                kind: InvariantKind::NoEgressOutsideAllowlist,
                applies_to_cases: Vec::new(),
            }],
            envelope: BehaviouralEnvelope {
                max_tokens_per_call: 128,
                max_tokens_per_run: 512,
                max_latency_ms_per_call: 1_000,
                max_latency_ms_per_run: 4_000,
                max_response_bytes_per_call: 4_096,
                max_fact_writes_per_call: 0,
                decay: DecayEnvelope {
                    min_half_life_seconds: 0,
                    max_refreshes_per_call: 0,
                },
                max_contradiction_rate_ppm: 0,
                undo: UndoEnvelope {
                    max_operations_per_call: 0,
                    max_latency_ms: 100,
                },
            },
            compatibility: CompatibilityAssertions {
                min_daemon_version: "0.5.0".to_string(),
                manifest_schema: crux_integrations::INTEGRATION_SCHEMA_V1.to_string(),
                supersedes: Vec::new(),
                migrations: Vec::new(),
                rollback_safe: true,
            },
        }
    }

    #[test]
    fn transition_on_a_missing_extension_is_not_found() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = FactStore::new();
        let err = set_lifecycle(
            &mut store,
            dir.path(),
            "ext.does-not-exist",
            PackLifecycleState::Active,
            None,
            None,
            1,
            crate::pack_replay::ActivationGate::Advisory,
        )
        .expect_err("not found");
        assert!(matches!(err, LifecycleError::NotFound(_)));
    }
}
