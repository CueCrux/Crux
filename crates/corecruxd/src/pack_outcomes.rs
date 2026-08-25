// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Per-pack outcome events — the M5 frontier seam of
//! `crux-daemon-buyer-fit-buildout-2026-07-13` that turns "what happened to
//! the memory this pack wrote" into something a score can be built from.
//!
//! `proof-carrying-adaptive-packs-2026-07-13` M3 needs decay, corrections,
//! rejected recalls and cross-agent signals **per pack**, and needs every
//! movement in the resulting score to trace back to a specific fact or
//! receipt. That traceability requirement is what shapes this module.
//!
//! ## Derived first, recorded only where nothing else can know
//!
//! Most outcomes are not events the daemon has to be told about — they are
//! properties of the store as it stands. A pack-written fact that a human
//! later overwrote *is* a correction; a pack-written fact past its freshness
//! horizon *is* decayed. So those are **derived** at read time by walking the
//! facts whose `actor` carries the pack's
//! [`PackAttribution::actor`](crate::extension_registry::PackAttribution::actor)
//! stamp — the seam #728 established.
//!
//! Deriving rather than recording buys three things:
//!
//! - **No write amplification and no hot-path change.** Nothing is appended
//!   on every store; `FactStore::store` is untouched.
//! - **Evidence that cannot go stale.** A recorded correction would be a
//!   claim about the past; a derived one is re-checked against the store
//!   every time it is read, and it names the `fact_id` that caused it.
//! - **Interpretability for free.** Every derived event carries the subject
//!   fact and the evidence that produced it, so "why did this pack's score
//!   move" is answerable by re-running the derivation.
//!
//! Dispatch history is likewise not re-recorded: the integrations audit tail
//! already holds every invoke, staged run, conformance run and lifecycle
//! move with the pack's `manifest_hash` on it, so this module reads that
//! trail rather than keeping a second copy that could disagree with it.
//!
//! What genuinely cannot be derived is a **judgement made elsewhere** — an
//! agent that saw a pack-written fact in recall and rejected it, or another
//! agent reporting an outcome about this pack. Those are **recorded**, via
//! [`record_outcome`], as facts under the pack's existing
//! `__extension__::{id}` entity. That prefix is already reserved and
//! force-private, so this adds no new on-disk artifact class and needs no
//! new storage-allowlist / projection / load-at-startup wiring.

use crate::extension_registry::{PackAttribution, EXTENSION_ENTITY_PREFIX, PACK_ACTOR_PREFIX};
use chrono::{DateTime, Utc};
use corecrux_memory::fact_store::{Fact, FactStore, StoreFact};
use corecrux_projections::decay::{self, Freshness};
use crux_integrations::IntegrationAuditEvent;
use crux_mcp::tools::freshness::fact_freshness;
use serde::{Deserialize, Serialize};

pub const PACK_OUTCOME_SCHEMA: &str = "crux.pack.outcome_event.v1";

/// Fact-key prefix under `__extension__::{id}` for a recorded outcome.
/// Distinct from the `record` key the install record uses, so an outcome
/// can never overwrite the registry row.
pub const OUTCOME_KEY_PREFIX: &str = "outcome:";

/// Cap on how much of the audit tail one derivation reads. The tail is a
/// whole-file read, so this bounds the cost of a listing on a long-lived
/// daemon rather than letting it grow with uptime.
pub const AUDIT_TAIL_SCAN_LIMIT: usize = 2_000;

/// What kind of thing happened to (or because of) a pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackOutcomeKind {
    /// A tool call succeeded.
    DispatchOk,
    /// A tool call was refused or failed.
    DispatchError,
    /// A staged run executed and committed nothing.
    StagedRun,
    /// A conformance replay completed.
    ConformanceRun,
    /// The pack moved between lifecycle states.
    LifecycleChanged,
    /// A fact this pack wrote was overwritten by a later version written by
    /// somebody else. The load-bearing negative signal: somebody had to fix
    /// what the pack said.
    Correction,
    /// A fact this pack wrote was explicitly retired by a newer fact under a
    /// different entity (cross-entity supersession).
    Superseded,
    /// A fact this pack wrote is past its freshness horizon.
    Decayed,
    /// An agent saw a pack-written fact in recall and rejected it. Cannot be
    /// derived — only the caller knows.
    RecallRejected,
    /// An agent saw a pack-written fact in recall and used it.
    RecallAccepted,
    /// Another agent's signal about this pack.
    CrossAgent,
}

impl PackOutcomeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DispatchOk => "dispatch_ok",
            Self::DispatchError => "dispatch_error",
            Self::StagedRun => "staged_run",
            Self::ConformanceRun => "conformance_run",
            Self::LifecycleChanged => "lifecycle_changed",
            Self::Correction => "correction",
            Self::Superseded => "superseded",
            Self::Decayed => "decayed",
            Self::RecallRejected => "recall_rejected",
            Self::RecallAccepted => "recall_accepted",
            Self::CrossAgent => "cross_agent",
        }
    }

    /// Kinds a caller may post. Everything else is derived, and accepting a
    /// posted copy of a derivable outcome would let a caller inflate or
    /// suppress a pack's record by asserting things the store contradicts.
    pub fn is_recordable(self) -> bool {
        matches!(self, Self::RecallRejected | Self::RecallAccepted | Self::CrossAgent)
    }
}

/// Where an event came from — the first thing a reader needs, because it
/// says whether the event is re-derivable or a stored assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackOutcomeSource {
    /// Re-computed from the fact store as it stands right now.
    DerivedFromFacts,
    /// Re-read from the integrations audit tail.
    DerivedFromAudit,
    /// Posted by a caller and persisted.
    Recorded,
}

/// The fact an outcome is about, when it is about one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackOutcomeSubject {
    pub entity: String,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fact_id: Option<String>,
}

/// One thing that happened, with the evidence that says so.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PackOutcomeEvent {
    pub schema: String,
    pub kind: PackOutcomeKind,
    pub source: PackOutcomeSource,
    /// The pack build this is about. Derived events carry the attribution
    /// parsed out of the subject fact's `actor`, so an event is about the
    /// bytes that wrote the fact rather than about whatever is installed
    /// under that id today.
    pub pack: PackAttribution,
    pub at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<PackOutcomeSubject>,
    /// Why this event exists, in a form a reader can check: the fact id that
    /// corrected the subject, the actor that did it, the audit action, the
    /// freshness class. This is what makes a score movement interpretable
    /// instead of asserted.
    pub evidence: serde_json::Value,
}

impl PackOutcomeEvent {
    fn new(
        kind: PackOutcomeKind,
        source: PackOutcomeSource,
        pack: PackAttribution,
        at_unix_ms: u64,
        subject: Option<PackOutcomeSubject>,
        evidence: serde_json::Value,
    ) -> Self {
        Self {
            schema: PACK_OUTCOME_SCHEMA.to_string(),
            kind,
            source,
            pack,
            at_unix_ms,
            subject,
            evidence,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OutcomeError {
    #[error("outcome kind '{0}' is derived from the store, not recorded — posting one would let a caller assert what the facts contradict")]
    NotRecordable(&'static str),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Parse a `pack:<id>@<version>#<hash>` actor stamp back into its parts.
///
/// The inverse of [`PackAttribution::actor`], and the reason that format was
/// chosen: an id can contain none of `@` or `#`, so a fact carrying the
/// stamp is self-describing with no registry lookup — which is what lets a
/// derived outcome name the pack build even after that build is uninstalled.
pub fn parse_pack_actor(actor: &str) -> Option<PackAttribution> {
    let rest = actor.strip_prefix(PACK_ACTOR_PREFIX)?;
    let (id, rest) = rest.split_once('@')?;
    let (version, manifest_hash) = rest.split_once('#')?;
    if id.is_empty() || version.is_empty() || manifest_hash.is_empty() {
        return None;
    }
    Some(PackAttribution::new(id, version, manifest_hash))
}

fn entity_for(extension_id: &str) -> String {
    format!("{EXTENSION_ENTITY_PREFIX}::{extension_id}")
}

/// Everything one recorded outcome needs. Grouped rather than passed as
/// eight positional arguments so a caller cannot silently swap two `&str`s
/// — the `IssueGrantInput` pattern the grants module already uses.
pub struct RecordOutcomeInput {
    pub pack: PackAttribution,
    pub kind: PackOutcomeKind,
    pub subject: Option<PackOutcomeSubject>,
    pub evidence: serde_json::Value,
    pub now_unix_ms: u64,
    /// Disambiguates two records landing in the same millisecond, so they
    /// are separate facts rather than versions of one.
    pub nonce: String,
}

/// Persist an outcome a caller observed and the daemon cannot derive.
///
/// Written under the pack's own `__extension__::{id}` entity with an
/// `outcome:` key, so it inherits the prefix's existing reserved + private
/// posture: no new artifact class, and never push-eligible to a remote.
/// The key embeds the timestamp and a nonce so concurrent records are
/// separate facts rather than versions of one.
pub fn record_outcome(
    store: &mut FactStore,
    extension_id: &str,
    input: RecordOutcomeInput,
) -> Result<PackOutcomeEvent, OutcomeError> {
    if !input.kind.is_recordable() {
        return Err(OutcomeError::NotRecordable(input.kind.as_str()));
    }
    let now_unix_ms = input.now_unix_ms;
    let event = PackOutcomeEvent::new(
        input.kind,
        PackOutcomeSource::Recorded,
        input.pack,
        now_unix_ms,
        input.subject,
        input.evidence,
    );
    let mut sf = StoreFact {
        tenant_hash: "default".to_string(),
        entity: entity_for(extension_id),
        key: format!("{OUTCOME_KEY_PREFIX}{now_unix_ms:013}-{}", input.nonce),
        value: serde_json::to_string(&event)?,
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        // The pack did not author this — an agent's judgement *about* the
        // pack is the agent's statement, and stamping it with the pack's
        // actor would make the pack look like the source of its own score.
        actor: None,
    };
    crate::fact_privacy::enforce_global(&mut sf);
    store.try_store(sf)?;
    Ok(event)
}

/// Read back the outcomes a caller recorded for one pack.
pub fn recorded_outcomes(store: &FactStore, extension_id: &str) -> Vec<PackOutcomeEvent> {
    store
        .get_by_entity(&entity_for(extension_id))
        .into_iter()
        .filter(|fact| !fact.deleted && fact.key.starts_with(OUTCOME_KEY_PREFIX) && !fact.value.is_empty())
        .filter_map(|fact| serde_json::from_str::<PackOutcomeEvent>(&fact.value).ok())
        .collect()
}

/// Every fact currently in the store that this pack wrote.
///
/// Matched on the `actor` stamp rather than on an entity convention,
/// because a pack writes into the namespaces its grant allows — there is no
/// prefix that means "written by a pack".
///
/// Scanned per tenant, never over `all_facts()`: this runs on a request
/// path, the actor stamp carries no tenant, and an unfiltered scan would
/// let one tenant's outcome listing surface another's fact entities and
/// keys. The registry itself is single-tenant, so the caller passes
/// `default_tenant_hash()`; the parameter exists so that stays a decision
/// rather than an assumption.
pub fn facts_written_by(store: &FactStore, tenant_hash: &str, extension_id: &str) -> Vec<Fact> {
    let wanted = format!("{PACK_ACTOR_PREFIX}{extension_id}@");
    store
        .all_facts_for_tenant(tenant_hash)
        .filter(|fact| !fact.deleted)
        .filter(|fact| fact.actor.as_deref().is_some_and(|actor| actor.starts_with(&wanted)))
        .cloned()
        .collect()
}

/// Derive, from the store as it stands, what became of this pack's writes.
///
/// Three signals, each naming its evidence:
/// - **Correction** — a later version of the same `(entity, key)` carries a
///   different actor. Somebody had to fix what the pack said.
/// - **Superseded** — the fact was explicitly retired by a newer fact under
///   another entity (`superseded_by`).
/// - **Decayed** — the fact is past its freshness horizon.
///
/// A fact can produce more than one: being corrected and being stale are
/// independent facts about it, and collapsing them would hide one.
pub fn derive_fact_outcomes(
    store: &FactStore,
    tenant_hash: &str,
    extension_id: &str,
    now: DateTime<Utc>,
) -> Vec<PackOutcomeEvent> {
    let policy = decay::DecayPolicy::from_env();
    let mut out = Vec::new();

    for fact in facts_written_by(store, tenant_hash, extension_id) {
        let Some(pack) = fact.actor.as_deref().and_then(parse_pack_actor) else {
            continue;
        };
        let subject = PackOutcomeSubject {
            entity: fact.entity.clone(),
            key: fact.key.clone(),
            fact_id: Some(fact.fact_id.clone()),
        };

        if let Some(successor) = later_version_by_another_actor(store, &fact) {
            out.push(PackOutcomeEvent::new(
                PackOutcomeKind::Correction,
                PackOutcomeSource::DerivedFromFacts,
                pack.clone(),
                successor.stored_at.timestamp_millis().max(0) as u64,
                Some(subject.clone()),
                serde_json::json!({
                    "corrected_by_fact_id": successor.fact_id,
                    "corrected_by_actor": successor.actor,
                    "pack_version": fact.version,
                    "corrected_version": successor.version,
                }),
            ));
        }

        if let Some(by) = fact.superseded_by.as_deref() {
            out.push(PackOutcomeEvent::new(
                PackOutcomeKind::Superseded,
                PackOutcomeSource::DerivedFromFacts,
                pack.clone(),
                fact.stored_at.timestamp_millis().max(0) as u64,
                Some(subject.clone()),
                serde_json::json!({ "superseded_by_fact_id": by }),
            ));
        }

        // The shared recall-time helper, not a second decay computation:
        // "stale" here has to mean exactly what it means in recall, or a
        // pack is penalised for facts users still see.
        let freshness = fact_freshness(&fact, now, policy);
        if freshness == Freshness::Stale {
            out.push(PackOutcomeEvent::new(
                PackOutcomeKind::Decayed,
                PackOutcomeSource::DerivedFromFacts,
                pack,
                now.timestamp_millis().max(0) as u64,
                Some(subject),
                serde_json::json!({
                    "horizon_class": fact.horizon_class.as_str(),
                    "freshness": freshness.as_str(),
                    "stored_at_unix_ms": fact.stored_at.timestamp_millis(),
                    "reverified_at_unix_ms": fact.reverified_at.map(|at| at.timestamp_millis()),
                }),
            ));
        }
    }
    out
}

/// The newest version of this fact's `(entity, key)` chain that a different
/// actor wrote, if any.
///
/// A pack re-writing its own fact is the pack working, not a correction —
/// so only a *different* actor counts.
fn later_version_by_another_actor<'a>(store: &'a FactStore, fact: &Fact) -> Option<&'a Fact> {
    store
        .fact_history(&fact.tenant_hash, &fact.entity, &fact.key)
        .into_iter()
        .filter(|candidate| candidate.version > fact.version)
        .filter(|candidate| candidate.actor.as_deref() != fact.actor.as_deref())
        .max_by_key(|candidate| candidate.version)
}

/// Map the integrations audit tail onto outcome events for one pack.
///
/// The tail already records every invoke, staged run, conformance run and
/// lifecycle move with the pack's `manifest_hash` attached (the #728 seam),
/// so this reads it rather than keeping a parallel log that could disagree
/// with the audit trail an operator actually inspects.
pub fn derive_audit_outcomes(audit: &[IntegrationAuditEvent], extension_id: &str) -> Vec<PackOutcomeEvent> {
    audit
        .iter()
        .filter(|event| event.pack_id == extension_id)
        .filter_map(|event| {
            let kind = match event.action.as_str() {
                crux_integrations::AUDIT_EXTENSION_INVOKE_OK => PackOutcomeKind::DispatchOk,
                crux_integrations::AUDIT_EXTENSION_INVOKE_REJECTED => PackOutcomeKind::DispatchError,
                crux_integrations::AUDIT_EXTENSION_INVOKE_STAGED => PackOutcomeKind::StagedRun,
                crux_integrations::AUDIT_EXTENSION_CONFORMANCE_RUN => PackOutcomeKind::ConformanceRun,
                crux_integrations::AUDIT_EXTENSION_LIFECYCLE => PackOutcomeKind::LifecycleChanged,
                _ => return None,
            };
            // Without a manifest hash the row predates the attribution seam
            // and cannot be tied to a pack build. Dropping it is deliberate:
            // an event whose pack build is unknown would put un-attributable
            // evidence into a per-build score.
            let manifest_hash = event
                .detail
                .as_ref()
                .and_then(|detail| detail.get("manifest_hash"))
                .and_then(|value| value.as_str())?;
            Some(PackOutcomeEvent::new(
                kind,
                PackOutcomeSource::DerivedFromAudit,
                PackAttribution::new(&event.pack_id, &event.version, manifest_hash),
                event.ts_unix_ms,
                None,
                serde_json::json!({
                    "action": event.action,
                    "outcome": event.outcome,
                    "actor": event.actor,
                    "detail": event.detail,
                }),
            ))
        })
        .collect()
}

/// Counts by kind, for a caller that wants the shape of a pack's record
/// before it reads the events themselves.
pub fn totals(events: &[PackOutcomeEvent]) -> serde_json::Map<String, serde_json::Value> {
    let mut totals = serde_json::Map::new();
    for event in events {
        let entry = totals
            .entry(event.kind.as_str().to_string())
            .or_insert_with(|| serde_json::json!(0));
        let next = entry.as_u64().unwrap_or(0) + 1;
        *entry = serde_json::json!(next);
    }
    totals
}

/// Everything known about one pack's outcomes, newest last.
///
/// Ordering is by event time so a consumer can fold the sequence into a
/// score without sorting it first; ties keep insertion order, which puts a
/// fact-derived event next to the audit row from the same millisecond
/// rather than interleaving them arbitrarily.
pub fn collect_outcomes(
    store: &FactStore,
    audit: &[IntegrationAuditEvent],
    tenant_hash: &str,
    extension_id: &str,
    now: DateTime<Utc>,
) -> Vec<PackOutcomeEvent> {
    let mut events = derive_audit_outcomes(audit, extension_id);
    events.extend(derive_fact_outcomes(store, tenant_hash, extension_id, now));
    events.extend(recorded_outcomes(store, extension_id));
    events.sort_by_key(|event| event.at_unix_ms);
    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use corecrux_memory::fact_store::HorizonClass;

    /// The registry is single-tenant; every pack write lands here.
    const TENANT: &str = "default";

    const HASH: &str = "blake3:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

    fn attribution() -> PackAttribution {
        PackAttribution::new("ext.example.quote", "0.1.0", HASH)
    }

    fn pack_write(entity: &str, value: &str) -> StoreFact {
        StoreFact {
            tenant_hash: corecrux_memory::fact_store::default_tenant_hash(),
            entity: entity.to_string(),
            key: "content".to_string(),
            value: value.to_string(),
            source_receipt: None,
            confidence: 0.9,
            private: false,
            horizon_class: None,
            actor: Some(attribution().actor()),
        }
    }

    fn human_write(entity: &str, value: &str) -> StoreFact {
        StoreFact {
            actor: Some("p_alice".to_string()),
            ..pack_write(entity, value)
        }
    }

    fn audit_event(action: &str, detail: serde_json::Value, ts: u64) -> IntegrationAuditEvent {
        IntegrationAuditEvent::extension(
            ts,
            action,
            Some("p_alice"),
            "ext.example.quote",
            Some("0.1.0"),
            "ok",
            detail,
        )
    }

    /// The actor stamp round-trips, which is what lets a derived outcome
    /// name a pack build using only the fact.
    #[test]
    fn the_actor_stamp_round_trips() {
        let parsed = parse_pack_actor(&attribution().actor()).expect("parse");
        assert_eq!(parsed, attribution());

        assert!(parse_pack_actor("p_alice").is_none());
        assert!(parse_pack_actor("pack:ext.example.quote@0.1.0").is_none(), "no hash");
        assert!(
            parse_pack_actor("pack:ext.example.quote#blake3:x").is_none(),
            "no version"
        );
        assert!(parse_pack_actor("pack:@0.1.0#blake3:x").is_none(), "no id");
    }

    /// The load-bearing negative signal: somebody had to fix what the pack
    /// said, and the event names who and which fact.
    #[test]
    fn a_human_overwrite_of_a_pack_fact_derives_a_correction() {
        let mut store = FactStore::new();
        store.store(pack_write("personal::quotes::today", "Roses are red"));
        let correcting = store.store(human_write("personal::quotes::today", "Roses are actually pink"));

        let events = derive_fact_outcomes(&store, TENANT, "ext.example.quote", Utc::now());
        let correction = events
            .iter()
            .find(|event| event.kind == PackOutcomeKind::Correction)
            .expect("correction derived");
        assert_eq!(correction.source, PackOutcomeSource::DerivedFromFacts);
        assert_eq!(correction.pack, attribution());
        assert_eq!(
            correction.evidence.get("corrected_by_fact_id"),
            Some(&serde_json::json!(correcting.fact_id)),
            "the evidence has to name the fact that did the correcting, or the score is unauditable"
        );
        assert_eq!(
            correction.evidence.get("corrected_by_actor"),
            Some(&serde_json::json!("p_alice"))
        );
        assert_eq!(
            correction.subject.as_ref().map(|s| s.entity.as_str()),
            Some("personal::quotes::today")
        );
    }

    /// A pack updating its own fact is the pack working. Counting it as a
    /// correction would penalise exactly the packs that keep memory current.
    #[test]
    fn a_pack_updating_its_own_fact_is_not_a_correction() {
        let mut store = FactStore::new();
        store.store(pack_write("personal::quotes::today", "Roses are red"));
        store.store(pack_write("personal::quotes::today", "Violets are blue"));

        let events = derive_fact_outcomes(&store, TENANT, "ext.example.quote", Utc::now());
        assert!(
            !events.iter().any(|event| event.kind == PackOutcomeKind::Correction),
            "the pack's own update must not read as somebody correcting it"
        );
    }

    #[test]
    fn a_stale_pack_fact_derives_a_decay_event() {
        let mut store = FactStore::new();
        let mut write = pack_write("personal::quotes::today", "Roses are red");
        write.horizon_class = Some(HorizonClass::Volatile);
        store.store(write);

        let fresh = derive_fact_outcomes(&store, TENANT, "ext.example.quote", Utc::now());
        assert!(!fresh.iter().any(|event| event.kind == PackOutcomeKind::Decayed));

        let much_later = Utc::now() + chrono::Duration::days(3650);
        let decayed = derive_fact_outcomes(&store, TENANT, "ext.example.quote", much_later);
        let event = decayed
            .iter()
            .find(|event| event.kind == PackOutcomeKind::Decayed)
            .expect("decay derived");
        assert_eq!(event.evidence.get("freshness"), Some(&serde_json::json!("stale")));
        assert_eq!(event.pack, attribution());
    }

    /// Facts nobody's pack wrote must never enter a pack's record.
    #[test]
    fn another_writers_facts_are_not_attributed_to_the_pack() {
        let mut store = FactStore::new();
        store.store(human_write("personal::quotes::other", "not the pack's"));
        let mut other_pack = pack_write("personal::quotes::third", "another pack");
        other_pack.actor = Some(PackAttribution::new("ext.other.pack", "2.0.0", HASH).actor());
        store.store(other_pack);
        store.store(pack_write("personal::quotes::today", "Roses are red"));

        let mine = facts_written_by(&store, TENANT, "ext.example.quote");
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].entity, "personal::quotes::today");
    }

    /// `all_facts()` is documented internal/admin-only precisely because it
    /// skips the tenant filter, and this derivation runs on a request path.
    /// The actor stamp carries no tenant, so an unfiltered scan would let
    /// one tenant's outcome listing surface another's entities and keys.
    #[test]
    fn outcomes_never_cross_a_tenant_boundary() {
        let mut store = FactStore::new();
        let mut other_tenant = pack_write("personal::quotes::theirs", "another tenant's");
        other_tenant.tenant_hash = "other-tenant".to_string();
        store.store(other_tenant);
        store.store(pack_write("personal::quotes::today", "ours"));

        let ours = facts_written_by(&store, TENANT, "ext.example.quote");
        assert_eq!(ours.len(), 1);
        assert_eq!(ours[0].entity, "personal::quotes::today");

        let theirs = facts_written_by(&store, "other-tenant", "ext.example.quote");
        assert_eq!(theirs.len(), 1);
        assert_eq!(theirs[0].entity, "personal::quotes::theirs");

        let events = derive_fact_outcomes(&store, TENANT, "ext.example.quote", Utc::now());
        assert!(
            events
                .iter()
                .filter_map(|event| event.subject.as_ref())
                .all(|subject| subject.entity != "personal::quotes::theirs"),
            "another tenant's fact must not appear in this tenant's outcome listing"
        );
    }

    #[test]
    fn audit_rows_become_dispatch_and_lifecycle_outcomes() {
        let audit = vec![
            audit_event(
                crux_integrations::AUDIT_EXTENSION_INVOKE_OK,
                serde_json::json!({"manifest_hash": HASH, "tool_name": "quote.daily"}),
                10,
            ),
            audit_event(
                crux_integrations::AUDIT_EXTENSION_INVOKE_REJECTED,
                serde_json::json!({"manifest_hash": HASH, "reason": "tool_not_declared"}),
                20,
            ),
            audit_event(
                crux_integrations::AUDIT_EXTENSION_LIFECYCLE,
                serde_json::json!({"manifest_hash": HASH, "from": "staged", "to": "active"}),
                30,
            ),
            // Another pack's row, and a row from before the attribution seam.
            IntegrationAuditEvent::extension(
                40,
                crux_integrations::AUDIT_EXTENSION_INVOKE_OK,
                None,
                "ext.other.pack",
                Some("2.0.0"),
                "ok",
                serde_json::json!({"manifest_hash": HASH}),
            ),
            audit_event(
                crux_integrations::AUDIT_EXTENSION_INVOKE_OK,
                serde_json::json!({"tool_name": "quote.daily"}),
                50,
            ),
        ];

        let events = derive_audit_outcomes(&audit, "ext.example.quote");
        assert_eq!(
            events.len(),
            3,
            "another pack's row and an un-attributable row must both stay out"
        );
        assert_eq!(events[0].kind, PackOutcomeKind::DispatchOk);
        assert_eq!(events[1].kind, PackOutcomeKind::DispatchError);
        assert_eq!(events[2].kind, PackOutcomeKind::LifecycleChanged);
        assert!(events.iter().all(|event| event.pack.manifest_hash == HASH));
        assert!(events
            .iter()
            .all(|event| event.source == PackOutcomeSource::DerivedFromAudit));
    }

    /// A caller may post what only it can know, and may not post what the
    /// store already answers — otherwise a pack's record could be inflated
    /// by assertion.
    #[test]
    fn only_judgements_can_be_recorded_derivable_kinds_are_refused() {
        let mut store = FactStore::new();
        let subject = PackOutcomeSubject {
            entity: "personal::quotes::today".to_string(),
            key: "content".to_string(),
            fact_id: None,
        };

        let event = record_outcome(
            &mut store,
            "ext.example.quote",
            RecordOutcomeInput {
                pack: attribution(),
                kind: PackOutcomeKind::RecallRejected,
                subject: Some(subject.clone()),
                evidence: serde_json::json!({"reason": "contradicted the user"}),
                now_unix_ms: 1_000,
                nonce: "a".to_string(),
            },
        )
        .expect("recall rejection is recordable");
        assert_eq!(event.source, PackOutcomeSource::Recorded);

        for kind in [
            PackOutcomeKind::Correction,
            PackOutcomeKind::Decayed,
            PackOutcomeKind::DispatchOk,
        ] {
            let err = record_outcome(
                &mut store,
                "ext.example.quote",
                RecordOutcomeInput {
                    pack: attribution(),
                    kind,
                    subject: None,
                    evidence: serde_json::json!({}),
                    now_unix_ms: 1_000,
                    nonce: "b".to_string(),
                },
            )
            .expect_err("derivable kinds must be refused");
            assert!(matches!(err, OutcomeError::NotRecordable(_)));
        }

        let read_back = recorded_outcomes(&store, "ext.example.quote");
        assert_eq!(read_back.len(), 1, "only the one legitimate record persisted");
        assert_eq!(read_back[0].kind, PackOutcomeKind::RecallRejected);
        assert_eq!(read_back[0].subject.as_ref(), Some(&subject));
    }

    /// A recorded outcome must not be stamped with the pack's actor: an
    /// agent's judgement *about* a pack is the agent's, and stamping it
    /// would make the pack look like the source of its own score.
    #[test]
    fn a_recorded_outcome_is_not_authored_by_the_pack() {
        let mut store = FactStore::new();
        record_outcome(
            &mut store,
            "ext.example.quote",
            RecordOutcomeInput {
                pack: attribution(),
                kind: PackOutcomeKind::RecallRejected,
                subject: None,
                evidence: serde_json::json!({}),
                now_unix_ms: 1_000,
                nonce: "a".to_string(),
            },
        )
        .expect("record");
        assert!(
            facts_written_by(&store, TENANT, "ext.example.quote").is_empty(),
            "the outcome fact must not read as a pack write"
        );
    }

    #[test]
    fn collect_orders_by_time_and_totals_by_kind() {
        let mut store = FactStore::new();
        store.store(pack_write("personal::quotes::today", "Roses are red"));
        store.store(human_write("personal::quotes::today", "Roses are pink"));
        record_outcome(
            &mut store,
            "ext.example.quote",
            RecordOutcomeInput {
                pack: attribution(),
                kind: PackOutcomeKind::RecallRejected,
                subject: None,
                evidence: serde_json::json!({}),
                now_unix_ms: 17_700_000_000_000,
                nonce: "a".to_string(),
            },
        )
        .expect("record");
        let audit = vec![audit_event(
            crux_integrations::AUDIT_EXTENSION_INVOKE_OK,
            serde_json::json!({"manifest_hash": HASH}),
            1,
        )];

        let events = collect_outcomes(&store, &audit, TENANT, "ext.example.quote", Utc::now());
        assert!(
            events.windows(2).all(|pair| pair[0].at_unix_ms <= pair[1].at_unix_ms),
            "a consumer folds this sequence into a score; it has to arrive ordered"
        );
        assert_eq!(
            events.first().map(|event| event.kind),
            Some(PackOutcomeKind::DispatchOk)
        );

        let totals = totals(&events);
        assert_eq!(totals.get("dispatch_ok"), Some(&serde_json::json!(1)));
        assert_eq!(totals.get("correction"), Some(&serde_json::json!(1)));
        assert_eq!(totals.get("recall_rejected"), Some(&serde_json::json!(1)));
    }
}
