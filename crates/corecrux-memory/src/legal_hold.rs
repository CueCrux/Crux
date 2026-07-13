// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Durable legal holds over the fact store.
//!
//! Holds use the existing append-only fact journal rather than a new on-disk
//! artifact: `__legal_hold__::<id>` carries the latest state, and
//! `__legal_hold_receipt__::<receipt_id>` carries an override audit record.
//! Both prefixes are born private and excluded from portable memory exports.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::fact_store::{Fact, FactStore, HorizonClass, StoreFact};

pub const LEGAL_HOLD_SCHEMA_V1: &str = "crux.legal_hold.v1";
pub const LEGAL_HOLD_RECEIPT_SCHEMA_V1: &str = "crux.legal_hold.receipt.v1";
pub const LEGAL_HOLD_ENTITY_PREFIX: &str = "__legal_hold__::";
pub const LEGAL_HOLD_RECEIPT_ENTITY_PREFIX: &str = "__legal_hold_receipt__::";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct LegalHold {
    pub schema: String,
    pub hold_id: String,
    pub tenant_id: String,
    /// Empty means every entity in the tenant.
    #[serde(default)]
    pub entity_prefixes: Vec<String>,
    pub reason: String,
    pub placed_at: DateTime<Utc>,
    pub placed_by: String,
    pub place_receipt_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_receipt_id: Option<String>,
}

impl LegalHold {
    pub fn active(&self) -> bool {
        self.released_at.is_none()
    }

    pub fn covers(&self, tenant_id: &str, entity: &str) -> bool {
        self.active()
            && self.tenant_id == tenant_id
            && (self.entity_prefixes.is_empty() || self.entity_prefixes.iter().any(|prefix| entity.starts_with(prefix)))
    }

    pub fn covers_fact(&self, fact: &Fact) -> bool {
        self.covers(&fact.tenant_hash, &fact.entity)
    }
}

#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct PlaceLegalHold {
    pub tenant_id: String,
    #[serde(default)]
    pub entity_prefixes: Vec<String>,
    pub reason: String,
    #[serde(default)]
    pub actor: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub enum LegalHoldReceiptKind {
    #[serde(rename = "legal_hold_placed")]
    Placed,
    #[serde(rename = "legal_hold_released")]
    Released,
    #[serde(rename = "legal_hold_overridden")]
    Overridden,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct LegalHoldReceiptV1 {
    pub schema: String,
    pub receipt_id: String,
    pub kind: LegalHoldReceiptKind,
    pub hold_ids: Vec<String>,
    pub tenant_id: String,
    #[serde(default)]
    pub entity_prefixes: Vec<String>,
    pub reason: String,
    pub actor: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fact_ids: Vec<String>,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct LegalHoldMutation {
    pub hold: LegalHold,
    pub receipt: LegalHoldReceiptV1,
}

#[derive(Debug, Error)]
pub enum LegalHoldError {
    #[error("tenant_id is required")]
    MissingTenant,
    #[error("reason is required")]
    MissingReason,
    #[error("legal hold not found: {0}")]
    NotFound(String),
    #[error("legal hold is already released: {0}")]
    AlreadyReleased(String),
    #[error("legal hold persistence failed: {0}")]
    Persistence(#[from] std::io::Error),
    #[error("legal hold serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn opaque_id(prefix: &str) -> String {
    format!("{prefix}{}", uuid::Uuid::new_v4().simple())
}

fn normalize_prefixes(prefixes: Vec<String>) -> Vec<String> {
    let mut prefixes: Vec<String> = prefixes
        .into_iter()
        .map(|prefix| prefix.trim().to_string())
        .filter(|prefix| !prefix.is_empty())
        .collect();
    prefixes.sort();
    prefixes.dedup();
    prefixes
}

impl FactStore {
    pub fn place_legal_hold(&mut self, request: PlaceLegalHold) -> Result<LegalHoldMutation, LegalHoldError> {
        let tenant_id = request.tenant_id.trim().to_string();
        if tenant_id.is_empty() {
            return Err(LegalHoldError::MissingTenant);
        }
        let reason = request.reason.trim().to_string();
        if reason.is_empty() {
            return Err(LegalHoldError::MissingReason);
        }
        let actor = request.actor.unwrap_or_else(|| "operator".to_string());
        let hold_id = opaque_id("lh_");
        let receipt_id = opaque_id("r_legal_hold_place_");
        let now = Utc::now();
        let entity_prefixes = normalize_prefixes(request.entity_prefixes);
        let receipt = LegalHoldReceiptV1 {
            schema: LEGAL_HOLD_RECEIPT_SCHEMA_V1.to_string(),
            receipt_id: receipt_id.clone(),
            kind: LegalHoldReceiptKind::Placed,
            hold_ids: vec![hold_id.clone()],
            tenant_id: tenant_id.clone(),
            entity_prefixes: entity_prefixes.clone(),
            reason: reason.clone(),
            actor: actor.clone(),
            fact_ids: Vec::new(),
            recorded_at: now,
        };
        let hold = LegalHold {
            schema: LEGAL_HOLD_SCHEMA_V1.to_string(),
            hold_id: hold_id.clone(),
            tenant_id,
            entity_prefixes,
            reason,
            placed_at: now,
            placed_by: actor,
            place_receipt_id: receipt_id.clone(),
            released_at: None,
            released_by: None,
            release_receipt_id: None,
        };
        let value = serde_json::to_string(&hold)?;
        self.try_store(StoreFact {
            tenant_hash: hold.tenant_id.clone(),
            entity: format!("{LEGAL_HOLD_ENTITY_PREFIX}{hold_id}"),
            key: "state".to_string(),
            value,
            source_receipt: Some(receipt_id),
            confidence: 1.0,
            private: true,
            horizon_class: Some(HorizonClass::None),
            actor: Some(hold.placed_by.clone()),
        })?;
        Ok(LegalHoldMutation { hold, receipt })
    }

    pub fn release_legal_hold(
        &mut self,
        hold_id: &str,
        actor: Option<&str>,
    ) -> Result<LegalHoldMutation, LegalHoldError> {
        let mut hold = self
            .legal_hold(hold_id)
            .ok_or_else(|| LegalHoldError::NotFound(hold_id.to_string()))?;
        if !hold.active() {
            return Err(LegalHoldError::AlreadyReleased(hold_id.to_string()));
        }
        let actor = actor.unwrap_or("operator").to_string();
        let receipt_id = opaque_id("r_legal_hold_release_");
        let now = Utc::now();
        hold.released_at = Some(now);
        hold.released_by = Some(actor.clone());
        hold.release_receipt_id = Some(receipt_id.clone());
        let receipt = LegalHoldReceiptV1 {
            schema: LEGAL_HOLD_RECEIPT_SCHEMA_V1.to_string(),
            receipt_id: receipt_id.clone(),
            kind: LegalHoldReceiptKind::Released,
            hold_ids: vec![hold.hold_id.clone()],
            tenant_id: hold.tenant_id.clone(),
            entity_prefixes: hold.entity_prefixes.clone(),
            reason: hold.reason.clone(),
            actor: actor.clone(),
            fact_ids: Vec::new(),
            recorded_at: now,
        };
        let value = serde_json::to_string(&hold)?;
        self.try_store(StoreFact {
            tenant_hash: hold.tenant_id.clone(),
            entity: format!("{LEGAL_HOLD_ENTITY_PREFIX}{}", hold.hold_id),
            key: "state".to_string(),
            value,
            source_receipt: Some(receipt_id),
            confidence: 1.0,
            private: true,
            horizon_class: Some(HorizonClass::None),
            actor: Some(actor),
        })?;
        Ok(LegalHoldMutation { hold, receipt })
    }

    /// Bind the durable signed observation record produced by the daemon to
    /// the hold state. The fact-store receipt material is deliberately not
    /// represented as signed by itself; the HTTP layer signs it through the
    /// observation lane, then calls this method with that record id.
    pub fn attach_signed_legal_hold_receipt(
        &mut self,
        hold_id: &str,
        kind: LegalHoldReceiptKind,
        signed_record_id: &str,
    ) -> Result<LegalHold, LegalHoldError> {
        let mut hold = self
            .legal_hold(hold_id)
            .ok_or_else(|| LegalHoldError::NotFound(hold_id.to_string()))?;
        match kind {
            LegalHoldReceiptKind::Placed => hold.place_receipt_id = signed_record_id.to_string(),
            LegalHoldReceiptKind::Released => hold.release_receipt_id = Some(signed_record_id.to_string()),
            LegalHoldReceiptKind::Overridden => return Ok(hold),
        }
        self.try_store(StoreFact {
            tenant_hash: hold.tenant_id.clone(),
            entity: format!("{LEGAL_HOLD_ENTITY_PREFIX}{}", hold.hold_id),
            key: "state".to_string(),
            value: serde_json::to_string(&hold)?,
            source_receipt: Some(signed_record_id.to_string()),
            confidence: 1.0,
            private: true,
            horizon_class: Some(HorizonClass::None),
            actor: Some(hold.released_by.clone().unwrap_or_else(|| hold.placed_by.clone())),
        })?;
        Ok(hold)
    }

    pub fn legal_hold(&self, hold_id: &str) -> Option<LegalHold> {
        let entity = format!("{LEGAL_HOLD_ENTITY_PREFIX}{hold_id}");
        self.get_by_entity(&entity)
            .into_iter()
            .filter(|fact| fact.key == "state" && fact.superseded_by.is_none())
            .max_by(|left, right| left.version.cmp(&right.version))
            .and_then(|fact| serde_json::from_str(&fact.value).ok())
    }

    pub fn legal_holds(&self) -> Vec<LegalHold> {
        let mut holds: Vec<LegalHold> = self
            .all_facts()
            .filter(|fact| {
                !fact.deleted
                    && fact.superseded_by.is_none()
                    && fact.key == "state"
                    && fact.entity.starts_with(LEGAL_HOLD_ENTITY_PREFIX)
            })
            .filter_map(|fact| match serde_json::from_str(&fact.value) {
                Ok(hold) => Some(hold),
                Err(err) => {
                    tracing::warn!(fact_id = %fact.fact_id, ?err, "legal-hold-state-parse-skip");
                    None
                }
            })
            .collect();
        holds.sort_by(|left, right| {
            left.placed_at
                .cmp(&right.placed_at)
                .then_with(|| left.hold_id.cmp(&right.hold_id))
        });
        holds
    }

    pub fn active_legal_holds(&self) -> Vec<LegalHold> {
        self.legal_holds().into_iter().filter(LegalHold::active).collect()
    }

    pub fn covering_legal_holds(&self, tenant_id: &str, entity: &str) -> Vec<LegalHold> {
        self.active_legal_holds()
            .into_iter()
            .filter(|hold| hold.covers(tenant_id, entity))
            .collect()
    }

    pub fn deleted_facts_covered_by_legal_holds(&self) -> Vec<(String, Vec<String>)> {
        let holds = self.active_legal_holds();
        let mut covered: Vec<(String, Vec<String>)> = self
            .all_facts()
            .filter(|fact| fact.deleted)
            .filter_map(|fact| {
                let hold_ids: Vec<String> = holds
                    .iter()
                    .filter(|hold| hold.covers_fact(fact))
                    .map(|hold| hold.hold_id.clone())
                    .collect();
                (!hold_ids.is_empty()).then(|| (fact.fact_id.clone(), hold_ids))
            })
            .collect();
        covered.sort_by(|left, right| left.0.cmp(&right.0));
        covered
    }

    pub fn record_legal_hold_override(
        &mut self,
        tenant_id: &str,
        hold_ids: Vec<String>,
        fact_ids: Vec<String>,
        reason: &str,
        actor: &str,
    ) -> Result<LegalHoldReceiptV1, LegalHoldError> {
        let receipt_id = opaque_id("r_legal_hold_override_");
        let receipt = LegalHoldReceiptV1 {
            schema: LEGAL_HOLD_RECEIPT_SCHEMA_V1.to_string(),
            receipt_id: receipt_id.clone(),
            kind: LegalHoldReceiptKind::Overridden,
            hold_ids,
            tenant_id: tenant_id.to_string(),
            entity_prefixes: Vec::new(),
            reason: reason.to_string(),
            actor: actor.to_string(),
            fact_ids,
            recorded_at: Utc::now(),
        };
        self.try_store(StoreFact {
            tenant_hash: tenant_id.to_string(),
            entity: format!("{LEGAL_HOLD_RECEIPT_ENTITY_PREFIX}{receipt_id}"),
            key: "receipt".to_string(),
            value: serde_json::to_string(&receipt)?,
            source_receipt: Some(receipt_id),
            confidence: 1.0,
            private: true,
            horizon_class: Some(HorizonClass::None),
            actor: Some(actor.to_string()),
        })?;
        Ok(receipt)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fact(tenant: &str, entity: &str, key: &str) -> StoreFact {
        StoreFact {
            tenant_hash: tenant.to_string(),
            entity: entity.to_string(),
            key: key.to_string(),
            value: "value".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        }
    }

    #[test]
    fn place_release_are_private_receipted_and_survive_replay() {
        let dir = tempdir().unwrap();
        let hold_id;
        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let placed = store
                .place_legal_hold(PlaceLegalHold {
                    tenant_id: "tenant-a".to_string(),
                    entity_prefixes: vec!["customer::".to_string()],
                    reason: "litigation".to_string(),
                    actor: Some("p_operator".to_string()),
                })
                .unwrap();
            hold_id = placed.hold.hold_id.clone();
            assert_eq!(placed.receipt.kind, LegalHoldReceiptKind::Placed);
            let state = store.get_by_entity(&format!("{LEGAL_HOLD_ENTITY_PREFIX}{hold_id}"));
            assert_eq!(state.len(), 1);
            assert!(state[0].private);
            assert_eq!(
                state[0].source_receipt.as_deref(),
                Some(placed.receipt.receipt_id.as_str())
            );

            let released = store.release_legal_hold(&hold_id, Some("p_operator")).unwrap();
            assert_eq!(released.receipt.kind, LegalHoldReceiptKind::Released);
            assert!(!released.hold.active());
        }

        let replayed = FactStore::with_persistence(dir.path()).unwrap();
        let hold = replayed.legal_hold(&hold_id).unwrap();
        assert!(!hold.active());
        assert!(hold.release_receipt_id.is_some());
    }

    #[test]
    fn hold_scope_is_tenant_and_prefix_bounded() {
        let mut store = FactStore::new();
        store
            .place_legal_hold(PlaceLegalHold {
                tenant_id: "tenant-a".to_string(),
                entity_prefixes: vec!["customer::42::".to_string()],
                reason: "dispute".to_string(),
                actor: None,
            })
            .unwrap();
        assert_eq!(store.covering_legal_holds("tenant-a", "customer::42::profile").len(), 1);
        assert!(store
            .covering_legal_holds("tenant-a", "customer::7::profile")
            .is_empty());
        assert!(store
            .covering_legal_holds("tenant-b", "customer::42::profile")
            .is_empty());
    }

    #[test]
    fn retention_skips_facts_covered_by_active_hold() {
        let mut store = FactStore::new();
        let held = store.store(fact("tenant-a", "customer::42::profile", "held"));
        let unheld = store.store(fact("tenant-a", "customer::7::profile", "ordinary"));
        store
            .place_legal_hold(PlaceLegalHold {
                tenant_id: "tenant-a".to_string(),
                entity_prefixes: vec!["customer::42::".to_string()],
                reason: "litigation".to_string(),
                actor: None,
            })
            .unwrap();

        let marked = store.mark_retention_eligible(Utc::now() + chrono::Duration::seconds(1));
        assert!(!marked.contains(&held.fact_id));
        assert!(marked.contains(&unheld.fact_id));
        assert!(store.get(&held.fact_id).is_some());
        assert!(store.get(&unheld.fact_id).is_none());
    }

    #[test]
    fn hard_compaction_refuses_hold_without_complete_override_receipt() {
        let dir = tempdir().unwrap();
        let mut store = FactStore::with_persistence(dir.path()).unwrap();
        let held = store.store(fact("tenant-a", "customer::42::profile", "held"));
        let placed = store
            .place_legal_hold(PlaceLegalHold {
                tenant_id: "tenant-a".to_string(),
                entity_prefixes: vec!["customer::42::".to_string()],
                reason: "litigation".to_string(),
                actor: None,
            })
            .unwrap();
        assert!(store.delete(&held.fact_id));

        let err = store.compact_journal().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains(&placed.hold.hold_id));

        let incomplete = store
            .record_legal_hold_override(
                "tenant-a",
                vec![placed.hold.hold_id.clone()],
                Vec::new(),
                "GDPR Article 17 full-tenant erasure",
                "p_dpo",
            )
            .unwrap();
        let err = store
            .compact_journal_after_legal_hold_override_receipt(&incomplete)
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

        let complete = store
            .record_legal_hold_override(
                "tenant-a",
                vec![placed.hold.hold_id],
                vec![held.fact_id],
                "GDPR Article 17 full-tenant erasure",
                "p_dpo",
            )
            .unwrap();
        let report = store
            .compact_journal_after_legal_hold_override_receipt(&complete)
            .unwrap();
        assert_eq!(report.facts_dropped, 1);
        assert_eq!(complete.kind, LegalHoldReceiptKind::Overridden);
    }
}
