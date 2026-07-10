// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Agent handoff protocol for multi-agent delegation.
//!
//! Handoff packages are authenticated by the server using a keyed BLAKE3 MAC.
//! This lets the receiver verify that the package was minted by the current
//! CoreCrux MCP server, not self-signed by arbitrary user input.

use std::collections::BTreeSet;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use corecrux_memory::fact_store::{Fact, StoreFact};
use corecrux_memory::{FactStore, SessionStore};

use crate::scope;

const HANDOFF_SIGNATURE_ALG: &str = "blake3-mac-v1";

/// A structured statement of intent travelling with a handoff (Open Engine's
/// "task record" — audit §2.3). Without it the receiver reconstructs intent
/// from the bundled `facts` / `session_state` blob plus the free-text
/// `message`; with it the requester's outcome, curated sources, acceptance
/// criteria, boundaries, and blocker rule travel as first-class fields.
///
/// Every field is optional/empty-skipped: an all-empty `TaskRecord` serialises
/// to `{}` and a `HandoffPackage` with no record at all omits the block
/// entirely (back-compat — see `HandoffPackage::task_record`). The crypto
/// receipt is the surrounding `SignedHandoff`, so the 7th Open-Engine field
/// (receipt) is the envelope, not a member here.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskRecord {
    /// Who is asking (defaults to `source_agent` if unset).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<String>,
    /// The outcome the receiver should drive toward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desired_outcome: Option<String>,
    /// Curated source pointers (paths, urls, fact ids) — distinct from the
    /// auto-bundled `work_ids`, which point at work items not a source set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    /// What "done" means — checkable conditions, not prose.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acceptance_criteria: Vec<String>,
    /// What the receiver must NOT do (scope fences).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub boundaries: Vec<String>,
    /// When to stop and hand back (e.g. "block needs_approval before any
    /// deploy") — the rule, not an after-the-fact blocker note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocker_rule: Option<String>,
}

/// A handoff package containing session state and facts for delegation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffPackage {
    /// Logical session identifier as seen by MCP clients.
    pub session_id: String,
    pub session_state: Option<serde_json::Value>,
    pub facts: Vec<Fact>,
    pub created_at: String,
    pub source_agent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_agent: Option<String>,
    pub message: Option<String>,
    /// Agent-graph: work item ids bundled with this handoff so the receiver
    /// can pick up the queued work without a separate `list_work` round-trip.
    /// Additive + `#[serde(default)]` so existing packages deserialise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub work_ids: Vec<String>,
    /// Structured statement of intent (Open Engine task record). Optional +
    /// skip-if-`None`, and placed last so a package created without it
    /// serialises byte-identically to a pre-`task_record` package — legacy
    /// bundles verify unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_record: Option<TaskRecord>,
}

/// An authenticated handoff package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedHandoff {
    /// base64(JSON(HandoffPackage))
    pub payload_b64: String,
    /// BLAKE3 hex digest of the raw payload bytes.
    pub content_hash: String,
    /// base64(BLAKE3 keyed MAC of the payload bytes).
    pub signature_b64: String,
    /// Signature algorithm marker.
    pub signature_alg: String,
}

/// Result of accepting a handoff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptResult {
    pub session_loaded: bool,
    pub facts_loaded: usize,
    pub verified: bool,
    /// The handoff's task record, surfaced to the receiver so it can read the
    /// requester's intent without re-deriving it from facts. `None` for legacy
    /// (pre-`task_record`) packages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_record: Option<TaskRecord>,
}

/// Inputs required to build a handoff package.
#[derive(Debug, Clone)]
pub struct CreateHandoffRequest<'a> {
    pub session_id: &'a str,
    pub stored_session_id: &'a str,
    pub include_facts: bool,
    pub source_agent: &'a str,
    pub target_agent: Option<String>,
    pub message: Option<String>,
    /// Optional structured statement of intent to travel with the handoff.
    pub task_record: Option<TaskRecord>,
}

/// Errors that can occur during handoff creation or acceptance.
#[derive(Debug, thiserror::Error)]
pub enum HandoffError {
    #[error("session not found: {0}")]
    SessionNotFound(String),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("content hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("unsupported handoff signature algorithm: {0}")]
    UnsupportedSignatureAlgorithm(String),
    #[error("handoff is targeted to agent '{expected}' but receiver is '{actual}'")]
    TargetAgentMismatch { expected: String, actual: String },
    #[error("private facts in a handoff require an authenticated receiving agent")]
    ReceiverAgentRequired,
}

/// Create a signed handoff package from current session state and relevant facts.
pub fn create_handoff(
    session_store: &SessionStore,
    fact_store: &FactStore,
    request: CreateHandoffRequest<'_>,
    handoff_key: &[u8; 32],
) -> Result<SignedHandoff, HandoffError> {
    let session_state = session_store.get(request.stored_session_id).map(|s| s.state.clone());
    let facts = if request.include_facts {
        collect_relevant_facts(
            fact_store,
            request.session_id,
            session_state.as_ref(),
            Some(request.source_agent),
        )
    } else {
        Vec::new()
    };

    // Agent-graph (orchestrators plan, M5): bundle the work item ids the
    // receiver should pick up so it can resume without a separate `list_work`
    // round-trip. Sources, in order of precedence:
    //   1. work / execplan ids referenced anywhere in the session state JSON
    //   2. `__work__::<project>::<work_id>` record facts pulled into the bundle
    // Additive — empty when neither source yields ids (old behaviour).
    let work_ids = collect_work_ids(session_state.as_ref(), &facts);

    let package = HandoffPackage {
        session_id: request.session_id.to_string(),
        session_state,
        facts,
        created_at: Utc::now().to_rfc3339(),
        source_agent: request.source_agent.to_string(),
        target_agent: request.target_agent,
        message: request.message,
        work_ids,
        task_record: request.task_record,
    };

    let payload_json = serde_json::to_vec(&package)?;
    let payload_b64 = B64.encode(&payload_json);
    let content_hash = blake3::hash(&payload_json).to_hex().to_string();
    let signature_b64 = B64.encode(compute_mac(handoff_key, &payload_json));

    Ok(SignedHandoff {
        payload_b64,
        content_hash,
        signature_b64,
        signature_alg: HANDOFF_SIGNATURE_ALG.to_string(),
    })
}

/// Accept and verify a handoff, loading its contents into local stores.
pub fn accept_handoff(
    session_store: &mut SessionStore,
    fact_store: &mut FactStore,
    signed: &SignedHandoff,
    receiver_agent: Option<&str>,
    handoff_key: &[u8; 32],
) -> Result<AcceptResult, HandoffError> {
    if signed.signature_alg != HANDOFF_SIGNATURE_ALG {
        return Err(HandoffError::UnsupportedSignatureAlgorithm(
            signed.signature_alg.clone(),
        ));
    }

    let payload_bytes = B64.decode(&signed.payload_b64)?;
    let actual_hash = blake3::hash(&payload_bytes).to_hex().to_string();
    if actual_hash != signed.content_hash {
        return Err(HandoffError::HashMismatch {
            expected: signed.content_hash.clone(),
            actual: actual_hash,
        });
    }

    let expected_sig = compute_mac(handoff_key, &payload_bytes);
    let actual_sig = B64.decode(&signed.signature_b64)?;
    if actual_sig.as_slice() != expected_sig {
        return Err(HandoffError::SignatureInvalid);
    }

    let package: HandoffPackage = serde_json::from_slice(&payload_bytes)?;

    // Capture the task record before `package` is partially moved below, so it
    // can be surfaced to the receiver in the result.
    let task_record = package.task_record.clone();

    if let Some(target_agent) = &package.target_agent {
        let actual = receiver_agent.unwrap_or("anonymous").to_string();
        if receiver_agent != Some(target_agent.as_str()) {
            return Err(HandoffError::TargetAgentMismatch {
                expected: target_agent.clone(),
                actual,
            });
        }
    }

    let stored_session_id = scope::scoped_session_id(receiver_agent, &package.session_id);
    let session_loaded = if let Some(state) = package.session_state {
        session_store.put(&stored_session_id, state, None);
        true
    } else {
        false
    };

    let facts_loaded = package.facts.len();
    for fact in package.facts {
        let (entity, private) = if fact.private {
            let logical_entity = scope::visible_entity_for_agent(&fact, Some(&package.source_agent))
                .unwrap_or_else(|| fact.entity.clone());
            let receiver = receiver_agent.ok_or(HandoffError::ReceiverAgentRequired)?;
            (scope::private_entity_for_agent(receiver, &logical_entity), true)
        } else {
            (fact.entity, false)
        };

        fact_store.store(StoreFact {
            entity,
            key: fact.key,
            value: fact.value,
            source_receipt: fact.source_receipt,
            confidence: fact.confidence,
            private,
            horizon_class: None,
            actor: None,
        });
    }

    Ok(AcceptResult {
        session_loaded,
        facts_loaded,
        verified: true,
        task_record,
    })
}

fn compute_mac(handoff_key: &[u8; 32], payload_bytes: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(handoff_key, payload_bytes).as_bytes()
}

fn collect_relevant_facts(
    fact_store: &FactStore,
    session_id: &str,
    session_state: Option<&serde_json::Value>,
    agent_name: Option<&str>,
) -> Vec<Fact> {
    let referenced_ids = extract_fact_ids(session_state);
    let decision_entity = format!("__decisions__::{session_id}");

    let mut facts: Vec<Fact> = fact_store
        .all_facts()
        .filter(|fact| !fact.deleted)
        .filter(|fact| !fact.private)
        .filter(|fact| scope::fact_visible_to_agent(fact, agent_name))
        .filter(|fact| {
            let visible_entity = scope::visible_entity_for_agent(fact, agent_name);
            referenced_ids.contains(&fact.fact_id)
                || visible_entity.as_deref() == Some(session_id)
                || visible_entity.as_deref() == Some(decision_entity.as_str())
                || fact.entity == decision_entity
        })
        .cloned()
        .collect();

    facts.sort_by(|left, right| {
        left.stored_at
            .cmp(&right.stored_at)
            .then_with(|| left.fact_id.cmp(&right.fact_id))
    });
    facts
}

/// Collect work item ids to bundle on a handoff (orchestrators plan, M5).
///
/// Returns a deterministically-ordered, de-duplicated list drawn from:
///   - `w_…` and `execplan:…` ids referenced anywhere in the session state
///   - `__work__::<project>::<work_id>` entities present in the bundled facts
///     (the trailing `::`-separated segment is the work id)
fn collect_work_ids(session_state: Option<&serde_json::Value>, facts: &[Fact]) -> Vec<String> {
    let mut ids: BTreeSet<String> = BTreeSet::new();
    if let Some(state) = session_state {
        collect_work_ids_from_value(state, &mut ids);
    }
    for fact in facts {
        if fact.deleted {
            continue;
        }
        if let Some(rest) = fact.entity.strip_prefix("__work__::") {
            if let Some(work_id) = rest.rsplit("::").next() {
                if !work_id.is_empty() {
                    ids.insert(work_id.to_string());
                }
            }
        }
    }
    ids.into_iter().collect()
}

/// Recursively harvest work/execplan ids from a JSON value. A string is taken
/// as a work id when it starts with `w_` or `execplan:`.
fn collect_work_ids_from_value(value: &serde_json::Value, ids: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::String(text) => {
            if text.starts_with("w_") || text.starts_with("execplan:") {
                ids.insert(text.clone());
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_work_ids_from_value(item, ids);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values() {
                collect_work_ids_from_value(item, ids);
            }
        }
        _ => {}
    }
}

fn extract_fact_ids(value: Option<&serde_json::Value>) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    if let Some(value) = value {
        collect_fact_ids_from_value(value, &mut ids);
    }
    ids
}

fn collect_fact_ids_from_value(value: &serde_json::Value, ids: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::String(text) => {
            if text.starts_with("f_") {
                ids.insert(text.clone());
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_fact_ids_from_value(item, ids);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values() {
                collect_fact_ids_from_value(item, ids);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use serde_json::json;

    use corecrux_memory::fact_store::StoreFact;
    use corecrux_memory::{FactStore, SessionStore};

    use super::*;
    use crate::scope;

    const HANDOFF_KEY: [u8; 32] = [7_u8; 32];

    fn seed_stores() -> (SessionStore, FactStore) {
        let mut sessions = SessionStore::new();
        sessions.put(
            "sess_handoff",
            json!({
                "step": 3,
                "notes": "in progress",
                "context_refs": ["f_linked"]
            }),
            None,
        );

        let mut facts = FactStore::new();
        facts.store(StoreFact {
            entity: "sess_handoff".to_string(),
            key: "summary".to_string(),
            value: "handoff summary".to_string(),
            source_receipt: Some("rcpt_001".to_string()),
            confidence: 0.95,
            private: false,
            horizon_class: None,
            actor: None,
        });
        facts.store(StoreFact {
            entity: "__decisions__::sess_handoff".to_string(),
            key: "decision".to_string(),
            value: "Use canary rollout".to_string(),
            source_receipt: None,
            confidence: 0.9,
            private: false,
            horizon_class: None,
            actor: None,
        });
        let linked = facts.store(StoreFact {
            entity: "deploy".to_string(),
            key: "approach".to_string(),
            value: "linked by fact id".to_string(),
            source_receipt: None,
            confidence: 0.85,
            private: false,
            horizon_class: None,
            actor: None,
        });
        let mut session = sessions.get("sess_handoff").unwrap().state.clone();
        session["context_refs"] = json!([linked.fact_id.clone()]);
        sessions.put("sess_handoff", session, None);

        facts.store(StoreFact {
            entity: "testing".to_string(),
            key: "approach".to_string(),
            value: "unrelated fact".to_string(),
            source_receipt: None,
            confidence: 0.8,
            private: false,
            horizon_class: None,
            actor: None,
        });
        facts.store(StoreFact {
            entity: scope::private_entity_for_agent("agent-alpha", "notes"),
            key: "internal".to_string(),
            value: "private note".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        });

        (sessions, facts)
    }

    #[test]
    fn create_and_accept_roundtrip() {
        let (sessions, facts) = seed_stores();

        let signed = create_handoff(
            &sessions,
            &facts,
            CreateHandoffRequest {
                session_id: "sess_handoff",
                stored_session_id: "sess_handoff",
                include_facts: true,
                source_agent: "agent-alpha",
                target_agent: Some("agent-beta".to_string()),
                message: Some("Handing off deployment task".to_string()),
                task_record: None,
            },
            &HANDOFF_KEY,
        )
        .expect("create_handoff should succeed");

        assert!(!signed.payload_b64.is_empty());
        assert!(!signed.content_hash.is_empty());
        assert!(!signed.signature_b64.is_empty());
        assert_eq!(signed.signature_alg, HANDOFF_SIGNATURE_ALG);

        let mut recv_sessions = SessionStore::new();
        let mut recv_facts = FactStore::new();

        let result = accept_handoff(
            &mut recv_sessions,
            &mut recv_facts,
            &signed,
            Some("agent-beta"),
            &HANDOFF_KEY,
        )
        .expect("accept_handoff should succeed");

        assert!(result.session_loaded);
        assert_eq!(result.facts_loaded, 3);
        assert!(result.verified);

        let loaded = recv_sessions
            .get("__agent_session::agent-beta::sess_handoff")
            .expect("session should exist");
        assert_eq!(loaded.state["step"], 3);

        assert_eq!(recv_facts.count(), 3);
        let imported_values: Vec<String> = recv_facts
            .all_facts()
            .filter(|fact| !fact.deleted)
            .map(|fact| fact.value.clone())
            .collect();
        assert!(imported_values.iter().any(|value| value == "handoff summary"));
        assert!(imported_values.iter().any(|value| value == "Use canary rollout"));
        assert!(imported_values.iter().any(|value| value == "linked by fact id"));
        assert!(!imported_values.iter().any(|value| value == "private note"));
        assert!(!imported_values.iter().any(|value| value == "unrelated fact"));
    }

    #[test]
    fn tampered_payload_rejected() {
        let (sessions, facts) = seed_stores();
        let mut signed = create_handoff(
            &sessions,
            &facts,
            CreateHandoffRequest {
                session_id: "sess_handoff",
                stored_session_id: "sess_handoff",
                include_facts: true,
                source_agent: "agent-alpha",
                target_agent: None,
                message: None,
                task_record: None,
            },
            &HANDOFF_KEY,
        )
        .expect("create_handoff should succeed");

        signed.payload_b64 = B64.encode(b"tampered payload data");

        let mut recv_sessions = SessionStore::new();
        let mut recv_facts = FactStore::new();
        let err = accept_handoff(
            &mut recv_sessions,
            &mut recv_facts,
            &signed,
            Some("agent-beta"),
            &HANDOFF_KEY,
        )
        .expect_err("should reject tampered payload");

        assert!(matches!(err, HandoffError::HashMismatch { .. }));
    }

    #[test]
    fn wrong_signature_rejected() {
        let (sessions, facts) = seed_stores();
        let signed = create_handoff(
            &sessions,
            &facts,
            CreateHandoffRequest {
                session_id: "sess_handoff",
                stored_session_id: "sess_handoff",
                include_facts: true,
                source_agent: "agent-alpha",
                target_agent: None,
                message: None,
                task_record: None,
            },
            &HANDOFF_KEY,
        )
        .expect("create_handoff should succeed");

        let bad_signed = SignedHandoff {
            payload_b64: signed.payload_b64.clone(),
            content_hash: signed.content_hash.clone(),
            signature_b64: B64.encode([9_u8; 32]),
            signature_alg: signed.signature_alg.clone(),
        };

        let mut recv_sessions = SessionStore::new();
        let mut recv_facts = FactStore::new();
        let err = accept_handoff(
            &mut recv_sessions,
            &mut recv_facts,
            &bad_signed,
            Some("agent-beta"),
            &HANDOFF_KEY,
        )
        .expect_err("should reject bad signature");

        assert!(matches!(err, HandoffError::SignatureInvalid));
    }

    #[test]
    fn target_agent_mismatch_rejected() {
        let (sessions, facts) = seed_stores();
        let signed = create_handoff(
            &sessions,
            &facts,
            CreateHandoffRequest {
                session_id: "sess_handoff",
                stored_session_id: "sess_handoff",
                include_facts: false,
                source_agent: "agent-alpha",
                target_agent: Some("agent-beta".to_string()),
                message: None,
                task_record: None,
            },
            &HANDOFF_KEY,
        )
        .expect("create_handoff should succeed");

        let mut recv_sessions = SessionStore::new();
        let mut recv_facts = FactStore::new();
        let err = accept_handoff(
            &mut recv_sessions,
            &mut recv_facts,
            &signed,
            Some("agent-gamma"),
            &HANDOFF_KEY,
        )
        .expect_err("should reject wrong receiving agent");

        assert!(matches!(err, HandoffError::TargetAgentMismatch { .. }));
    }

    #[test]
    fn handoff_without_facts() {
        let (sessions, facts) = seed_stores();
        let signed = create_handoff(
            &sessions,
            &facts,
            CreateHandoffRequest {
                session_id: "sess_handoff",
                stored_session_id: "sess_handoff",
                include_facts: false,
                source_agent: "agent-alpha",
                target_agent: None,
                message: None,
                task_record: None,
            },
            &HANDOFF_KEY,
        )
        .expect("create_handoff should succeed");

        let mut recv_sessions = SessionStore::new();
        let mut recv_facts = FactStore::new();
        let result = accept_handoff(
            &mut recv_sessions,
            &mut recv_facts,
            &signed,
            Some("agent-beta"),
            &HANDOFF_KEY,
        )
        .expect("accept_handoff should succeed");

        assert!(result.session_loaded);
        assert_eq!(result.facts_loaded, 0);
        assert_eq!(recv_facts.count(), 0);
    }

    #[test]
    fn collect_work_ids_from_session_and_facts() {
        // Session state references a work id and an execplan id.
        let state = json!({
            "current": "w_alpha",
            "queue": ["w_beta", "execplan:my-plan", "not-a-work-id"],
            "nested": { "ref": "w_alpha" }
        });
        // A bundled __work__ record fact contributes a third work id.
        let mut fs = FactStore::new();
        let work_fact = fs.store(StoreFact {
            entity: "__work__::default::w_gamma".to_string(),
            key: "record".to_string(),
            value: "{}".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        let facts = vec![work_fact];
        let ids = collect_work_ids(Some(&state), &facts);
        // De-duplicated + sorted (BTreeSet): w_alpha appears once.
        assert_eq!(
            ids,
            vec![
                "execplan:my-plan".to_string(),
                "w_alpha".to_string(),
                "w_beta".to_string(),
                "w_gamma".to_string(),
            ]
        );
    }

    #[test]
    fn handoff_bundles_work_ids_and_old_packages_still_verify() {
        let (sessions, facts) = seed_stores();
        // Add a work id reference into the session state so the bundler picks it up.
        let mut s = sessions;
        let mut state = s.get("sess_handoff").unwrap().state.clone();
        state["active_work"] = json!(["w_handoff_demo"]);
        s.put("sess_handoff", state, None);

        let signed = create_handoff(
            &s,
            &facts,
            CreateHandoffRequest {
                session_id: "sess_handoff",
                stored_session_id: "sess_handoff",
                include_facts: false,
                source_agent: "agent-alpha",
                target_agent: None,
                message: None,
                task_record: None,
            },
            &HANDOFF_KEY,
        )
        .expect("create_handoff should succeed");

        // The package carries the work id...
        let payload: HandoffPackage =
            serde_json::from_slice(&B64.decode(&signed.payload_b64).unwrap()).expect("decode package");
        assert_eq!(payload.work_ids, vec!["w_handoff_demo".to_string()]);

        // ...and still verifies end-to-end (additive field doesn't break the MAC).
        let mut recv_sessions = SessionStore::new();
        let mut recv_facts = FactStore::new();
        let result = accept_handoff(&mut recv_sessions, &mut recv_facts, &signed, None, &HANDOFF_KEY)
            .expect("accept_handoff should succeed");
        assert!(result.verified);
    }

    #[test]
    fn handoff_without_session() {
        let sessions = SessionStore::new();
        let facts = FactStore::new();
        let signed = create_handoff(
            &sessions,
            &facts,
            CreateHandoffRequest {
                session_id: "no_such_session",
                stored_session_id: "no_such_session",
                include_facts: false,
                source_agent: "agent-alpha",
                target_agent: None,
                message: None,
                task_record: None,
            },
            &HANDOFF_KEY,
        )
        .expect("create_handoff should succeed even without session");

        let mut recv_sessions = SessionStore::new();
        let mut recv_facts = FactStore::new();
        let result = accept_handoff(
            &mut recv_sessions,
            &mut recv_facts,
            &signed,
            Some("agent-beta"),
            &HANDOFF_KEY,
        )
        .expect("accept_handoff should succeed");

        assert!(!result.session_loaded);
        assert_eq!(result.facts_loaded, 0);
    }

    // --- M2: structured task_record --------------------------------------

    fn sample_task_record() -> TaskRecord {
        TaskRecord {
            requester: Some("claude-work".to_string()),
            desired_outcome: Some("wire the dense lane".to_string()),
            sources: vec!["crates/corecrux-retrieval/src/dense.rs".to_string()],
            acceptance_criteria: vec!["cargo test green".to_string()],
            boundaries: vec!["do not touch the GPU path".to_string()],
            blocker_rule: Some("block needs_approval before any deploy".to_string()),
        }
    }

    #[test]
    fn task_record_roundtrips_and_surfaces_on_accept() {
        let (sessions, facts) = seed_stores();
        let record = sample_task_record();

        let signed = create_handoff(
            &sessions,
            &facts,
            CreateHandoffRequest {
                session_id: "sess_handoff",
                stored_session_id: "sess_handoff",
                include_facts: false,
                source_agent: "agent-alpha",
                target_agent: Some("codex-work".to_string()),
                message: None,
                task_record: Some(record.clone()),
            },
            &HANDOFF_KEY,
        )
        .expect("create");

        let mut recv_sessions = SessionStore::new();
        let mut recv_facts = FactStore::new();
        let result = accept_handoff(
            &mut recv_sessions,
            &mut recv_facts,
            &signed,
            Some("codex-work"),
            &HANDOFF_KEY,
        )
        .expect("accept");

        assert!(result.verified);
        assert_eq!(
            result.task_record.as_ref(),
            Some(&record),
            "the receiver sees the requester's intent"
        );
    }

    #[test]
    fn legacy_package_without_task_record_serializes_identically_and_verifies() {
        let (sessions, facts) = seed_stores();

        // A package created with no task_record must be byte-identical to a
        // pre-M2 package: the field is omitted entirely from the JSON.
        let signed = create_handoff(
            &sessions,
            &facts,
            CreateHandoffRequest {
                session_id: "sess_handoff",
                stored_session_id: "sess_handoff",
                include_facts: false,
                source_agent: "agent-alpha",
                target_agent: Some("agent-beta".to_string()),
                message: None,
                task_record: None,
            },
            &HANDOFF_KEY,
        )
        .expect("create");

        let payload = B64.decode(&signed.payload_b64).expect("decode");
        let payload_str = String::from_utf8(payload).expect("utf8");
        assert!(
            !payload_str.contains("task_record"),
            "absent task_record is omitted from the wire (back-compat)"
        );

        // And it still verifies + accept tolerates the absent block.
        let mut recv_sessions = SessionStore::new();
        let mut recv_facts = FactStore::new();
        let result = accept_handoff(
            &mut recv_sessions,
            &mut recv_facts,
            &signed,
            Some("agent-beta"),
            &HANDOFF_KEY,
        )
        .expect("accept");
        assert!(result.verified);
        assert_eq!(result.task_record, None);
    }

    #[test]
    fn empty_task_record_serializes_to_empty_object() {
        let json = serde_json::to_string(&TaskRecord::default()).expect("serialize");
        assert_eq!(json, "{}", "every field is skip-if-empty");
    }

    #[test]
    fn tampered_task_record_fails_signature() {
        let (sessions, facts) = seed_stores();
        let signed = create_handoff(
            &sessions,
            &facts,
            CreateHandoffRequest {
                session_id: "sess_handoff",
                stored_session_id: "sess_handoff",
                include_facts: false,
                source_agent: "agent-alpha",
                target_agent: None,
                message: None,
                task_record: Some(sample_task_record()),
            },
            &HANDOFF_KEY,
        )
        .expect("create");

        // Re-encode the payload with a mutated task_record but keep the old
        // signature → the keyed MAC must reject it.
        let payload = B64.decode(&signed.payload_b64).expect("decode");
        let mut package: HandoffPackage = serde_json::from_slice(&payload).expect("parse");
        package.task_record.as_mut().unwrap().desired_outcome = Some("exfiltrate secrets".to_string());
        let tampered_json = serde_json::to_vec(&package).expect("reserialize");
        let tampered = SignedHandoff {
            payload_b64: B64.encode(&tampered_json),
            content_hash: blake3::hash(&tampered_json).to_hex().to_string(),
            signature_b64: signed.signature_b64.clone(), // stale signature
            signature_alg: signed.signature_alg.clone(),
        };

        let mut recv_sessions = SessionStore::new();
        let mut recv_facts = FactStore::new();
        let err = accept_handoff(&mut recv_sessions, &mut recv_facts, &tampered, None, &HANDOFF_KEY)
            .expect_err("tampered payload must fail verification");
        assert!(matches!(err, HandoffError::SignatureInvalid));
    }
}
