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
use std::collections::BTreeSet;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateObservation {
    pub local_passport_fpr: String,
    pub observed_subject: String,
    pub tenant_id: String,
    pub project_id: Option<String>,
    pub observed_at_unix_ms: u64,
    pub evidence_ref: String,
    pub cruxpack_source_receipt: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProposerConfig {
    pub temporal_window_ms: u64,
    pub project_window_ms: u64,
    pub min_confidence: f32,
}

impl Default for ProposerConfig {
    fn default() -> Self {
        Self {
            temporal_window_ms: 10 * 60 * 1000,
            project_window_ms: 24 * 60 * 60 * 1000,
            min_confidence: 0.75,
        }
    }
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

pub fn observations_from_session_bindings(facts: &FactStore) -> Vec<CandidateObservation> {
    crate::session_bindings::list_bindings(facts)
        .into_iter()
        .filter_map(|binding| {
            let passport = crate::passports::get_passport(facts, &binding.passport_id)?;
            Some(CandidateObservation {
                local_passport_fpr: passport.principal_id.clone(),
                observed_subject: passport.principal_id,
                tenant_id: binding.tenant_id,
                project_id: binding.project_id,
                observed_at_unix_ms: binding.bound_at_unix_ms,
                evidence_ref: format!("session_binding:{}", binding.session_id_hex),
                cruxpack_source_receipt: None,
            })
        })
        .collect()
}

pub fn propose_from_session_bindings(
    entities: &mut EntityStore,
    facts: &FactStore,
    actor: &str,
    config: &ProposerConfig,
) -> Result<Vec<(String, CandidateLinkPayload)>, CandidateLinkError> {
    let observations = observations_from_session_bindings(facts);
    propose_from_observations(entities, facts, &observations, actor, config)
}

pub fn propose_from_observations(
    entities: &mut EntityStore,
    facts: &FactStore,
    observations: &[CandidateObservation],
    actor: &str,
    config: &ProposerConfig,
) -> Result<Vec<(String, CandidateLinkPayload)>, CandidateLinkError> {
    let mut created = Vec::new();
    let mut sorted = observations.to_vec();
    sorted.sort_by(|a, b| {
        a.observed_at_unix_ms
            .cmp(&b.observed_at_unix_ms)
            .then_with(|| a.evidence_ref.cmp(&b.evidence_ref))
    });

    for i in 0..sorted.len() {
        for j in (i + 1)..sorted.len() {
            let a = &sorted[i];
            let b = &sorted[j];
            let Some(input) = proposal_input_for_pair(a, b, config) else {
                continue;
            };
            match create_candidate(entities, facts, input, actor) {
                Ok(candidate) => created.push(candidate),
                Err(CandidateLinkError::AlreadyExists(_)) => {}
                Err(err) => return Err(err),
            }
        }
    }
    Ok(created)
}

fn proposal_input_for_pair(
    a: &CandidateObservation,
    b: &CandidateObservation,
    config: &ProposerConfig,
) -> Option<CreateCandidateInput> {
    if a.tenant_id != b.tenant_id || a.observed_subject == b.observed_subject {
        return None;
    }

    let delta = a.observed_at_unix_ms.abs_diff(b.observed_at_unix_ms);
    let same_project = match (&a.project_id, &b.project_id) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    };
    let same_cruxpack = match (&a.cruxpack_source_receipt, &b.cruxpack_source_receipt) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    };

    let mut signals = Vec::new();
    if same_project && delta <= config.temporal_window_ms {
        signals.push(CandidateLinkSignal {
            kind: "temporal_adjacency".to_string(),
            confidence: 0.82,
            evidence_ref: Some(format!("{}|{}", a.evidence_ref, b.evidence_ref)),
        });
    }
    if same_project && delta <= config.project_window_ms {
        signals.push(CandidateLinkSignal {
            kind: "tenant_project_overlap".to_string(),
            confidence: 0.74,
            evidence_ref: Some(format!("{}|{}", a.evidence_ref, b.evidence_ref)),
        });
    }
    if same_cruxpack {
        signals.push(CandidateLinkSignal {
            kind: "cruxpack_provenance_match".to_string(),
            confidence: 0.86,
            evidence_ref: a.cruxpack_source_receipt.clone(),
        });
    }
    if signals.is_empty() {
        return None;
    }

    let confidence = signals.iter().map(|signal| signal.confidence).sum::<f32>() / signals.len() as f32;
    if confidence < config.min_confidence {
        return None;
    }

    let mut evidence_refs = BTreeSet::new();
    evidence_refs.insert(a.evidence_ref.clone());
    evidence_refs.insert(b.evidence_ref.clone());
    if let Some(receipt) = &a.cruxpack_source_receipt {
        evidence_refs.insert(receipt.clone());
    }
    if let Some(receipt) = &b.cruxpack_source_receipt {
        evidence_refs.insert(receipt.clone());
    }

    Some(CreateCandidateInput {
        local_passport_fpr: a.local_passport_fpr.clone(),
        observed_subject: b.observed_subject.clone(),
        signals,
        confidence,
        evidence_refs: evidence_refs.into_iter().collect(),
        proposed_at: None,
    })
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

    #[test]
    fn session_binding_proposer_emits_temporal_project_candidate() {
        let (dir, mut facts, mut entities, _) = seeded();
        let b1 = crate::session_bindings::resolve(
            &facts,
            crate::session_bindings::ResolveInput {
                session_id_hex: "sess-a",
                project_id: Some("alpha".to_string()),
                tenant_id: Some("work::team".to_string()),
                passport_id: Some("personal-default".to_string()),
                now_unix_ms: 1_000,
            },
        )
        .expect("binding 1");
        let b2 = crate::session_bindings::resolve(
            &facts,
            crate::session_bindings::ResolveInput {
                session_id_hex: "sess-b",
                project_id: Some("alpha".to_string()),
                tenant_id: Some("work::team".to_string()),
                passport_id: Some("work-default".to_string()),
                now_unix_ms: 2_000,
            },
        )
        .expect("binding 2");
        crate::session_bindings::write_binding(&mut facts, &b1).expect("write 1");
        crate::session_bindings::write_binding(&mut facts, &b2).expect("write 2");

        let created = propose_from_session_bindings(&mut entities, &facts, "operator", &ProposerConfig::default())
            .expect("propose");
        assert_eq!(created.len(), 1);
        let signals: Vec<String> = created[0].1.signals.iter().map(|signal| signal.kind.clone()).collect();
        assert!(signals.contains(&"temporal_adjacency".to_string()));
        assert!(signals.contains(&"tenant_project_overlap".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proposer_holds_decoy_with_different_tenant() {
        let (dir, facts, mut entities, local_fpr) = seeded();
        let observations = vec![
            CandidateObservation {
                local_passport_fpr: local_fpr.clone(),
                observed_subject: "p_remote_a".to_string(),
                tenant_id: "work::team-a".to_string(),
                project_id: Some("alpha".to_string()),
                observed_at_unix_ms: 1_000,
                evidence_ref: "session_binding:a".to_string(),
                cruxpack_source_receipt: None,
            },
            CandidateObservation {
                local_passport_fpr: local_fpr,
                observed_subject: "p_remote_b".to_string(),
                tenant_id: "work::team-b".to_string(),
                project_id: Some("alpha".to_string()),
                observed_at_unix_ms: 1_100,
                evidence_ref: "session_binding:b".to_string(),
                cruxpack_source_receipt: None,
            },
        ];

        let created = propose_from_observations(
            &mut entities,
            &facts,
            &observations,
            "operator",
            &ProposerConfig::default(),
        )
        .expect("propose");
        assert!(created.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cruxpack_provenance_proposer_emits_candidate() {
        let (dir, facts, mut entities, local_fpr) = seeded();
        let observations = vec![
            CandidateObservation {
                local_passport_fpr: local_fpr.clone(),
                observed_subject: "p_remote_a".to_string(),
                tenant_id: "personal".to_string(),
                project_id: None,
                observed_at_unix_ms: 1_000,
                evidence_ref: "fact:f1".to_string(),
                cruxpack_source_receipt: Some("cruxpack:blake3:abc".to_string()),
            },
            CandidateObservation {
                local_passport_fpr: local_fpr,
                observed_subject: "p_remote_b".to_string(),
                tenant_id: "personal".to_string(),
                project_id: None,
                observed_at_unix_ms: 86_400_000,
                evidence_ref: "fact:f2".to_string(),
                cruxpack_source_receipt: Some("cruxpack:blake3:abc".to_string()),
            },
        ];

        let created = propose_from_observations(
            &mut entities,
            &facts,
            &observations,
            "operator",
            &ProposerConfig::default(),
        )
        .expect("propose");
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].1.signals[0].kind, "cruxpack_provenance_match");
        assert!(created[0].1.evidence_refs.contains(&"cruxpack:blake3:abc".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proposer_skips_duplicate_candidates() {
        let (dir, facts, mut entities, local_fpr) = seeded();
        let observations = vec![
            CandidateObservation {
                local_passport_fpr: local_fpr.clone(),
                observed_subject: "p_remote_a".to_string(),
                tenant_id: "personal".to_string(),
                project_id: Some("alpha".to_string()),
                observed_at_unix_ms: 1_000,
                evidence_ref: "session_binding:a".to_string(),
                cruxpack_source_receipt: None,
            },
            CandidateObservation {
                local_passport_fpr: local_fpr,
                observed_subject: "p_remote_b".to_string(),
                tenant_id: "personal".to_string(),
                project_id: Some("alpha".to_string()),
                observed_at_unix_ms: 2_000,
                evidence_ref: "session_binding:b".to_string(),
                cruxpack_source_receipt: None,
            },
        ];

        let first = propose_from_observations(
            &mut entities,
            &facts,
            &observations,
            "operator",
            &ProposerConfig::default(),
        )
        .expect("first");
        let second = propose_from_observations(
            &mut entities,
            &facts,
            &observations,
            "operator",
            &ProposerConfig::default(),
        )
        .expect("second");
        assert_eq!(first.len(), 1);
        assert!(second.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
