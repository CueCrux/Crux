// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Candidate identity-link payloads.
//!
//! Storage lives in `EntityStore` under kind `candidate_link`. A candidate is
//! a suggestion only: resolvers must never follow this kind. Promotion to a
//! resolving `identity_link` requires the existing cross-signature ceremony.

use serde::{Deserialize, Serialize};

pub const CANDIDATE_LINK_KIND: &str = "candidate_link";
pub const CANDIDATE_LINK_SCHEMA_V1: &str = "crux.candidate_link.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CandidateLinkSignal {
    pub kind: String,
    /// Score in the closed range 0.0..=1.0.
    pub confidence: f32,
    /// Reference to evidence the operator can inspect; do not embed raw PII.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CandidateLinkStatus {
    Proposed,
    Confirmed,
    Rejected,
}

impl CandidateLinkStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Confirmed => "confirmed",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CandidateLinkPayload {
    pub schema_version: String,
    pub local_passport_fpr: String,
    pub observed_subject: String,
    #[serde(default)]
    pub signals: Vec<CandidateLinkSignal>,
    /// Overall proposer confidence in the closed range 0.0..=1.0.
    pub confidence: f32,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    pub proposed_at: String,
    pub status: CandidateLinkStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_link_id: Option<String>,
}

/// `cl_<first-16-hex-of-blake3(canonical candidate identity)>`.
pub fn candidate_link_id(payload: &CandidateLinkPayload) -> String {
    let identity = serde_json::json!({
        "local_passport_fpr": &payload.local_passport_fpr,
        "observed_subject": &payload.observed_subject,
        "signals": &payload.signals,
        "evidence_refs": &payload.evidence_refs,
    });
    let bytes = serde_json::to_vec(&identity).unwrap_or_default();
    format!("cl_{}", hex::encode(&blake3::hash(&bytes).as_bytes()[..8]))
}

pub fn validate_candidate_payload(payload: &CandidateLinkPayload) -> Result<(), String> {
    if payload.schema_version != CANDIDATE_LINK_SCHEMA_V1 {
        return Err(format!("unsupported schema_version '{}'", payload.schema_version));
    }
    if payload.local_passport_fpr.trim().is_empty() {
        return Err("local_passport_fpr must not be empty".to_string());
    }
    if payload.observed_subject.trim().is_empty() {
        return Err("observed_subject must not be empty".to_string());
    }
    if !(0.0..=1.0).contains(&payload.confidence) {
        return Err("confidence must be in 0.0..=1.0".to_string());
    }
    for signal in &payload.signals {
        if signal.kind.trim().is_empty() {
            return Err("signal kind must not be empty".to_string());
        }
        if !(0.0..=1.0).contains(&signal.confidence) {
            return Err("signal confidence must be in 0.0..=1.0".to_string());
        }
    }
    match payload.status {
        CandidateLinkStatus::Confirmed if payload.resolved_link_id.as_deref().unwrap_or("").is_empty() => {
            Err("confirmed candidates require resolved_link_id".to_string())
        }
        CandidateLinkStatus::Proposed | CandidateLinkStatus::Rejected
            if payload.resolved_link_id.as_deref().is_some_and(|id| !id.is_empty()) =>
        {
            Err("only confirmed candidates may carry resolved_link_id".to_string())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> CandidateLinkPayload {
        CandidateLinkPayload {
            schema_version: CANDIDATE_LINK_SCHEMA_V1.to_string(),
            local_passport_fpr: "p_local".to_string(),
            observed_subject: "anon-session:abc".to_string(),
            signals: vec![CandidateLinkSignal {
                kind: "temporal_adjacency".to_string(),
                confidence: 0.8,
                evidence_ref: Some("evidence:1".to_string()),
            }],
            confidence: 0.8,
            evidence_refs: vec!["evidence:1".to_string()],
            proposed_at: "2026-06-15T00:00:00Z".to_string(),
            status: CandidateLinkStatus::Proposed,
            resolved_link_id: None,
        }
    }

    #[test]
    fn candidate_id_ignores_proposed_at_but_includes_evidence() {
        let first = payload();
        let mut second = first.clone();
        second.proposed_at = "2026-06-16T00:00:00Z".to_string();
        assert_eq!(candidate_link_id(&first), candidate_link_id(&second));
        second.evidence_refs.push("evidence:2".to_string());
        assert_ne!(candidate_link_id(&first), candidate_link_id(&second));
    }

    #[test]
    fn validation_requires_confirmed_link_id_only_for_confirmed_status() {
        let mut p = payload();
        validate_candidate_payload(&p).expect("valid proposed");
        p.resolved_link_id = Some("il_x".to_string());
        assert!(validate_candidate_payload(&p).is_err());
        p.status = CandidateLinkStatus::Confirmed;
        validate_candidate_payload(&p).expect("confirmed with link");
    }
}
