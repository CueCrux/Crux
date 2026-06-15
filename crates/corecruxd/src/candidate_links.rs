// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Candidate identity-link storage.
//!
//! Candidates are proposal records only. They live in the local `EntityStore`
//! as kind `candidate_link`; the resolver never reads this kind. Confirming a
//! candidate is a later ceremony that creates a separate `identity_link`.

use chrono::Utc;
use corecrux_memory::candidate_link::{
    candidate_link_id, validate_candidate_payload, CandidateLinkPayload, CandidateLinkSignal, CandidateLinkStatus,
    CANDIDATE_LINK_KIND, CANDIDATE_LINK_SCHEMA_V1,
};
use corecrux_memory::{EntityQuery, EntityStore, FactStore};

#[derive(Debug, thiserror::Error)]
pub enum CandidateLinkError {
    #[error("local passport fingerprint '{0}' not found")]
    LocalPassportNotFound(String),
    #[error("candidate '{0}' already exists")]
    AlreadyExists(String),
    #[error("candidate '{0}' not found")]
    NotFound(String),
    #[error("invalid candidate: {0}")]
    Invalid(String),
    #[error("entity store error: {0}")]
    Store(String),
}

#[derive(Debug, Clone)]
pub struct CreateCandidateInput {
    pub local_passport_fpr: String,
    pub observed_subject: String,
    pub signals: Vec<CandidateLinkSignal>,
    pub confidence: f32,
    pub evidence_refs: Vec<String>,
    pub proposed_at: Option<String>,
}

fn ensure_local_passport_fpr(facts: &FactStore, fpr: &str) -> Result<(), CandidateLinkError> {
    if crate::passports::list_passports(facts, None)
        .into_iter()
        .any(|passport| passport.principal_id == fpr)
    {
        Ok(())
    } else {
        Err(CandidateLinkError::LocalPassportNotFound(fpr.to_string()))
    }
}

pub fn create_candidate(
    entities: &mut EntityStore,
    facts: &FactStore,
    input: CreateCandidateInput,
    actor: &str,
) -> Result<(String, CandidateLinkPayload), CandidateLinkError> {
    ensure_local_passport_fpr(facts, &input.local_passport_fpr)?;
    let payload = CandidateLinkPayload {
        schema_version: CANDIDATE_LINK_SCHEMA_V1.to_string(),
        local_passport_fpr: input.local_passport_fpr,
        observed_subject: input.observed_subject,
        signals: input.signals,
        confidence: input.confidence,
        evidence_refs: input.evidence_refs,
        proposed_at: input.proposed_at.unwrap_or_else(|| Utc::now().to_rfc3339()),
        status: CandidateLinkStatus::Proposed,
        resolved_link_id: None,
    };
    validate_candidate_payload(&payload).map_err(CandidateLinkError::Invalid)?;
    let candidate_id = candidate_link_id(&payload);
    if entities.get(CANDIDATE_LINK_KIND, &candidate_id).is_some() {
        return Err(CandidateLinkError::AlreadyExists(candidate_id));
    }
    let value = serde_json::to_value(&payload).map_err(|e| CandidateLinkError::Store(e.to_string()))?;
    entities
        .upsert(CANDIDATE_LINK_KIND, &candidate_id, value, actor, None)
        .map_err(|e| CandidateLinkError::Store(e.to_string()))?;
    Ok((candidate_id, payload))
}

pub fn get_candidate(entities: &EntityStore, candidate_id: &str) -> Option<CandidateLinkPayload> {
    entities
        .get(CANDIDATE_LINK_KIND, candidate_id)
        .and_then(|record| serde_json::from_value::<CandidateLinkPayload>(record.payload.clone()).ok())
}

pub fn list_candidates(
    entities: &EntityStore,
    status: Option<CandidateLinkStatus>,
) -> Vec<(String, CandidateLinkPayload)> {
    entities
        .list(&EntityQuery {
            kind: Some(CANDIDATE_LINK_KIND.to_string()),
            limit: None,
            include_deleted: false,
        })
        .into_iter()
        .filter_map(|record| {
            serde_json::from_value::<CandidateLinkPayload>(record.payload.clone())
                .ok()
                .filter(|payload| status.as_ref().is_none_or(|wanted| payload.status == *wanted))
                .map(|payload| (record.id.clone(), payload))
        })
        .collect()
}

pub fn update_candidate_status(
    entities: &mut EntityStore,
    candidate_id: &str,
    status: CandidateLinkStatus,
    resolved_link_id: Option<String>,
    actor: &str,
) -> Result<CandidateLinkPayload, CandidateLinkError> {
    let record = entities
        .get(CANDIDATE_LINK_KIND, candidate_id)
        .ok_or_else(|| CandidateLinkError::NotFound(candidate_id.to_string()))?;
    let mut payload: CandidateLinkPayload =
        serde_json::from_value(record.payload.clone()).map_err(|e| CandidateLinkError::Store(e.to_string()))?;
    payload.status = status;
    payload.resolved_link_id = resolved_link_id;
    validate_candidate_payload(&payload).map_err(CandidateLinkError::Invalid)?;
    let value = serde_json::to_value(&payload).map_err(|e| CandidateLinkError::Store(e.to_string()))?;
    entities
        .upsert(CANDIDATE_LINK_KIND, candidate_id, value, actor, None)
        .map_err(|e| CandidateLinkError::Store(e.to_string()))?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!("corecruxd-candidate-links-{name}-{nanos}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    fn seeded() -> (std::path::PathBuf, FactStore, EntityStore, String) {
        let dir = temp_dir("seeded");
        let mut facts = FactStore::new();
        crate::passports::seed_defaults_if_missing(&dir, &mut facts, 1).expect("seed");
        let local_fpr = crate::passports::get_passport(&facts, "personal-default")
            .expect("passport")
            .principal_id;
        (dir, facts, EntityStore::new(), local_fpr)
    }

    fn input(local_fpr: String) -> CreateCandidateInput {
        CreateCandidateInput {
            local_passport_fpr: local_fpr,
            observed_subject: "anon-session:alpha".to_string(),
            signals: vec![CandidateLinkSignal {
                kind: "temporal_adjacency".to_string(),
                confidence: 0.76,
                evidence_ref: Some("evidence:temporal:1".to_string()),
            }],
            confidence: 0.76,
            evidence_refs: vec!["evidence:temporal:1".to_string()],
            proposed_at: Some("2026-06-15T00:00:00Z".to_string()),
        }
    }

    #[test]
    fn create_get_list_candidate_records_actor_stamped_version() {
        let (dir, facts, mut entities, local_fpr) = seeded();
        let (candidate_id, payload) =
            create_candidate(&mut entities, &facts, input(local_fpr), "operator").expect("create");
        assert!(candidate_id.starts_with("cl_"));
        assert_eq!(payload.status, CandidateLinkStatus::Proposed);

        let stored = get_candidate(&entities, &candidate_id).expect("stored");
        assert_eq!(stored.observed_subject, "anon-session:alpha");
        let listed = list_candidates(&entities, Some(CandidateLinkStatus::Proposed));
        assert_eq!(listed.len(), 1);
        let record = entities.get(CANDIDATE_LINK_KIND, &candidate_id).expect("record");
        assert_eq!(record.actor, "operator");
        assert_eq!(record.version, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn duplicate_candidate_is_rejected() {
        let (dir, facts, mut entities, local_fpr) = seeded();
        let create = input(local_fpr);
        create_candidate(&mut entities, &facts, create.clone(), "operator").expect("first");
        assert!(matches!(
            create_candidate(&mut entities, &facts, create, "operator"),
            Err(CandidateLinkError::AlreadyExists(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn status_update_is_versioned_and_confirmed_requires_link_id() {
        let (dir, facts, mut entities, local_fpr) = seeded();
        let (candidate_id, _) = create_candidate(&mut entities, &facts, input(local_fpr), "operator").expect("create");

        let err = update_candidate_status(
            &mut entities,
            &candidate_id,
            CandidateLinkStatus::Confirmed,
            None,
            "operator",
        )
        .expect_err("confirmed requires link");
        assert!(matches!(err, CandidateLinkError::Invalid(_)));

        let confirmed = update_candidate_status(
            &mut entities,
            &candidate_id,
            CandidateLinkStatus::Confirmed,
            Some("il_abc".to_string()),
            "operator",
        )
        .expect("confirm");
        assert_eq!(confirmed.resolved_link_id.as_deref(), Some("il_abc"));
        assert_eq!(entities.history(CANDIDATE_LINK_KIND, &candidate_id).len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_local_passport_fpr_is_rejected() {
        let (dir, facts, mut entities, _) = seeded();
        assert!(matches!(
            create_candidate(&mut entities, &facts, input("p_unknown".to_string()), "operator"),
            Err(CandidateLinkError::LocalPassportNotFound(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
